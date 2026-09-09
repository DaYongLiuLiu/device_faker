//! COW 属性伪造引擎。
//!
//! - 已有属性：bionic `__system_property_find()` + COW remap + 原地 patch
//! - 不存在属性：COW remap + `MmapPropArea::emplace()` 在私有副本中插入 trie 节点
//!   （不依赖 companion resetprop，per-process 隔离零驻留）
//!
//! # 实现说明
//!
//! 不存在属性的插入通过 `MmapPropArea`（ksu_props）在 COW-remapped 内存上操作：
//! - `transmute((ptr, len))` → `MmapMut` 构造 `MmapPropArea`（MmapMut = `{ptr, len}` on Unix）
//! - `ManuallyDrop` 防止 `MmapPropArea` drop → `MmapMut` drop → munmap（COW 副本需保持存活）
//! - `emplace()` 内部 bump allocator 分配 trie 节点 + prop_info，Release store 发布指针

use std::{cell::RefCell, collections::HashMap};

use log::{info, warn};
use prop_rs_android::mmap_prop_area::{MmapPropArea, PROP_INFO_LONG_FLAG};

// ── bionic 类型定义 ────────────────────────────────────────────────────────

type FnSystemPropertyFind = unsafe extern "C" fn(*const libc::c_char) -> *const libc::c_void;

const PROP_VALUE_MAX: usize = 92;

// ── COW 范围缓存（per-thread，避免重复 remap 同一区域）────────────────────

struct PropRange {
    start: usize,
    end: usize,
}

thread_local! {
    // 已用 const {} 包裹，此 nightly 的 lint 仍误报（bug），allow 压制。
    #[allow(clippy::missing_const_for_thread_local)]
    static COW_RANGES: RefCell<Vec<PropRange>> = const { RefCell::new(Vec::new()) };
}

// ── 前缀 → area 路径缓存（per-thread，首次遍历后记住正确的 area）──────────

thread_local! {
    // HashMap::new 在此 toolchain 上非 const fn，无法按 clippy 建议包成 const。
    #[allow(clippy::missing_const_for_thread_local)]
    static PREFIX_AREA_CACHE: RefCell<HashMap<String, Vec<String>>> = RefCell::new(HashMap::new());
}

// ── bionic 符号加载 ────────────────────────────────────────────────────────

fn sys_prop_find() -> Option<FnSystemPropertyFind> {
    let sym = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"__system_property_find".as_ptr()) };
    if sym.is_null() {
        None
    } else {
        Some(unsafe { std::mem::transmute::<*mut libc::c_void, FnSystemPropertyFind>(sym) })
    }
}

// ── 入口 ───────────────────────────────────────────────────────────────────

/// 对目标进程的所有属性应用 COW 伪造。
///
/// - 已有属性：COW remap + 原地 patch
/// - 不存在属性：在对应 prop_area 的 COW 映射中插入 trie 节点 + prop_info
///
/// 返回仍未能处理的属性列表（映射找不到或空间不足），供 companion resetprop 兜底。
pub fn apply_cow_spoof(
    prop_map: &HashMap<String, String>,
) -> anyhow::Result<Vec<(String, String)>> {
    let mut unfound: Vec<(String, String)> = Vec::new();

    if prop_map.is_empty() {
        return Ok(unfound);
    }

    let find_fn = match sys_prop_find() {
        Some(f) => f,
        None => {
            anyhow::bail!("__system_property_find not available (dlsym failed)");
        }
    };

    // 长值不预过滤：ksu_props ≥ ddb6ee7 的 `update()` 原地支持任意长度的新值
    // （≥ PROP_VALUE_MAX 时内部 allocate 新 long buffer 并改写 prop_info 的
    // long offset），inline→long、long→更长都直接成功；只有全新属性走
    // emplace(long) 插入路径。
    let filtered: Vec<(&str, &str)> = prop_map
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    // 预热：逐 key 调用 find()，触发 bionic 对尚未映射 context area 的
    // 惰性映射（本进程域允许的 area 在此刻完成映射；被 SELinux 拒绝的
    // context 返回 null，内核 audit 自动去重）。之后再收集映射快照，
    // 确保快照覆盖本进程全部可映射的 area。
    //
    // sys_prop 先于预热初始化：context 路由与映射快照均依赖其内部
    // PropertyContext 状态，提前初始化保证后续地址一致。
    let _ = sys_prop_available();
    for (key, _) in &filtered {
        if let Ok(ckey) = std::ffi::CString::new(*key) {
            unsafe { find_fn(ckey.as_ptr()) };
        }
    }
    let mappings = collect_prop_area_mappings();

    // 预初始化 serial area（供所有 update() 调用共享）
    let mut serial_pa = match cow_serial_area(&mappings) {
        Ok(pa) => Some(pa),
        Err(e) => {
            warn!("Failed to COW serial area: {e}, patches will use fallback");
            None
        }
    };

    let mut cow_patched = 0usize;
    let mut cow_inserted = 0usize;
    let mut cow_skipped = 0usize;

    for (key, value) in &filtered {
        // Context 路由目标 area 未映射进本进程（预热后仍未映射 = SELinux
        // 拒绝，如 build_bootimage_prop 仅 shell/update_engine 可读）⇒
        // 属性对本进程不可观察：真实值与伪装值对 app 内检测代码均为
        // unknown，无泄漏面，静默跳过（不进 unfound）。
        if let Some(path) = context_area_path(key)
            && !mappings.iter().any(|m| m.path == path)
        {
            info!("COW skip '{key}': routed area {path} unmapped in process (unobservable)");
            cow_skipped += 1;
            continue;
        }

        match cow_patch_existing(find_fn, key, value, &mappings, serial_pa.as_deref_mut()) {
            Ok(true) => cow_patched += 1,
            Ok(false) => {
                // 属性不存在 → 尝试在 COW prop_area 中插入新 trie 节点
                match cow_patch_new(key, value, &mappings, find_fn) {
                    Ok(true) => cow_inserted += 1,
                    Ok(false) => {
                        unfound.push((key.to_string(), value.to_string()));
                    }
                    Err(e) => {
                        warn!("COW insert failed for '{key}': {e}");
                        unfound.push((key.to_string(), value.to_string()));
                    }
                }
            }
            Err(e) => warn!("COW patch failed for '{key}': {e}"),
        }
    }

    if cow_patched > 0 || cow_inserted > 0 {
        info!(
            "COW spoof: {cow_patched} patched, {cow_inserted} inserted, {cow_skipped} skipped (unobservable), {} total",
            filtered.len()
        );
    }

    COW_RANGES.with(|r| r.borrow_mut().clear());
    Ok(unfound)
}

// ── 已有属性：COW patch ────────────────────────────────────────────────────

/// 判断路径是否为 build 相关的 prop_area。
fn is_build_area(path: &str) -> bool {
    path.contains("build_prop")
        || path.contains("build_odm_prop")
        || path.contains("build_vendor_prop")
        || path.contains("default_prop")
}

fn cow_patch_existing(
    find_fn: FnSystemPropertyFind,
    key: &str,
    value: &str,
    mappings: &[PropAreaMapping],
    mut serial_pa: Option<&mut MmapPropArea>,
) -> anyhow::Result<bool> {
    use memmap2::MmapMut;

    let ckey =
        std::ffi::CString::new(key).map_err(|_| anyhow::anyhow!("invalid property name: {key}"))?;
    let prop_ptr = unsafe { find_fn(ckey.as_ptr()) };
    if prop_ptr.is_null() {
        return Ok(false);
    }

    // ── Phase 1: patch __system_property_find 返回的 area ────────────────
    if ensure_prop_area_private(prop_ptr as *const u8, mappings).is_err() {
        return Ok(false);
    }

    let primary_mapping = mappings
        .iter()
        .find(|m| {
            let addr = prop_ptr as usize;
            addr >= m.start && addr < m.end
        })
        .ok_or_else(|| anyhow::anyhow!("mapping not found for prop_ptr"))?;

    let size = primary_mapping.end - primary_mapping.start;
    let ptr = primary_mapping.start as *mut u8;
    let mmap_mut = unsafe { std::mem::transmute::<(*mut u8, usize), MmapMut>((ptr, size)) };
    let mut area = std::mem::ManuallyDrop::new(MmapPropArea::new(mmap_mut)?);

    let data_off = match area.find(key)? {
        Some(off) => off,
        None => {
            // MmapPropArea::find 找不到，尝试直接用 prop_ptr offset
            let prop_offset = (prop_ptr as usize) - primary_mapping.start;
            info!(
                "COW Phase1: '{key}' MmapPropArea::find returned None in {path}, \
                 prop_ptr offset={prop_offset:#x}, trying direct offset",
                path = primary_mapping.path
            );
            return Ok(false);
        }
    };

    info!(
        "COW Phase1: '{key}' found at offset={data_off:#x} in {path}, prop_ptr@{pp:#x}",
        path = primary_mapping.path,
        pp = prop_ptr as usize
    );

    let pa = serial_pa
        .as_deref_mut()
        .ok_or_else(|| anyhow::anyhow!("serial area not available"))?;
    // ksu_props ≥ ddb6ee7：`update()` 原地支持 ≥ PROP_VALUE_MAX 的长值——内部重新
    // 分配 long buffer 并改写 prop_info 的 long offset，prop_info 地址与 trie 布局
    // 不变（旧 buffer 内容保留，并发读者不会读到撕裂值）。
    // 不再需要 remove+emplace：那样会丢弃原 prop_info 节点、改变 trie 布局，
    // 且缓存了 prop_info* 的读法会读到墓碑。
    // 返回的 need_rebuild 表示旧 long buffer 成为孤儿；COW 是私有副本，随进程
    // 消亡，无需 rebuild。
    let mut need_rebuild = false;
    area.update(data_off, value, pa, &mut need_rebuild)
        .map_err(|e| anyhow::anyhow!("COW Phase1: update '{key}' failed: {e}"))?;

    // ── Phase 2: 扫描其他 build area，patch bionic prefix routing 可能命中的区域 ──
    // OnePlus/OPPO 设备上 __system_property_find 返回 build_prop 指针，但 bionic 的
    // __system_property_get 按 prefix routing 读 build_odm_prop。需要 patch 所有包含
    // 该属性的 build area。
    let primary_addr = prop_ptr as usize;
    let mut cross_patched = 0usize;

    for mapping in mappings {
        if !is_build_area(&mapping.path) {
            continue;
        }
        // 跳过 Phase 1 已 patch 的 area
        if primary_addr >= mapping.start && primary_addr < mapping.end {
            continue;
        }
        let msize = mapping.end - mapping.start;
        if msize < 128 {
            continue;
        }
        if ensure_prop_area_private(mapping.start as *const u8, mappings).is_err() {
            info!(
                "COW cross-area: skip {p} (COW remap failed)",
                p = mapping.path
            );
            continue;
        }
        let mptr = mapping.start as *mut u8;
        let mmap_mut = unsafe { std::mem::transmute::<(*mut u8, usize), MmapMut>((mptr, msize)) };
        let mut cross_area = match MmapPropArea::new(mmap_mut) {
            Ok(a) => std::mem::ManuallyDrop::new(a),
            Err(e) => {
                info!(
                    "COW cross-area: skip {p} (MmapPropArea::new failed: {e})",
                    p = mapping.path
                );
                continue;
            }
        };
        match cross_area.find(key) {
            Ok(Some(off)) => {
                if let Some(pa) = serial_pa.as_deref_mut() {
                    // 同 Phase 1：长值由 update() 原地处理，无需 remove+emplace
                    let mut need_rebuild = false;
                    match cross_area.update(off, value, pa, &mut need_rebuild) {
                        Ok(()) => {
                            cross_patched += 1;
                            info!("COW cross-area: '{key}' patched in {p}", p = mapping.path);
                        }
                        Err(e) => {
                            warn!(
                                "COW cross-area: update '{key}' failed in {p}: {e}",
                                p = mapping.path
                            );
                        }
                    }
                }
            }
            Ok(None) => {
                info!("COW cross-area: '{key}' not found in {p}", p = mapping.path);
            }
            Err(e) => {
                info!(
                    "COW cross-area: '{key}' find error in {p}: {e}",
                    p = mapping.path
                );
            }
        }
    }

    if cross_patched > 0 {
        info!(
            "COW cross-area: '{key}' patched in {n} additional area(s)",
            n = cross_patched
        );
    }

    Ok(true)
}

/// munmap `/dev/__properties__/*` 中路径匹配指定模式的映射。
/// 这些属性值为空，munmap 不影响任何功能。
pub fn unmap_prop_areas(patterns: &[String]) {
    if patterns.is_empty() {
        return;
    }

    let Ok(maps) = std::fs::read_to_string("/proc/self/maps") else {
        return;
    };

    for line in maps.lines() {
        if !line.contains("/dev/__properties__/") {
            continue;
        }
        if !patterns.iter().any(|p| line.contains(p.as_str())) {
            continue;
        }

        let mut ws = line.split_whitespace();
        let Some(range) = ws.next() else { continue };

        let Some((start_s, end_s)) = range.split_once('-') else {
            continue;
        };
        let Ok(start) = usize::from_str_radix(start_s, 16) else {
            continue;
        };
        let Ok(end) = usize::from_str_radix(end_s, 16) else {
            continue;
        };

        let size = end - start;
        let ret = unsafe { libc::munmap(start as *mut libc::c_void, size) };
        if ret == 0 {
            info!("Unmapped prop area: {range}");
        }
    }
}

// ── 映射收集 ───────────────────────────────────────────────────────────────

struct PropAreaMapping {
    start: usize,
    end: usize,
    path: String,
    offset: u64,
}

fn collect_prop_area_mappings() -> Vec<PropAreaMapping> {
    let Ok(maps) = std::fs::read_to_string("/proc/self/maps") else {
        return vec![];
    };

    let mut result = vec![];
    for line in maps.lines() {
        let mut ws = line.split_whitespace();
        let Some(range) = ws.next() else { continue };
        let Some(_perms) = ws.next() else { continue };
        let Some(off_str) = ws.next() else { continue };
        let Some(_dev) = ws.next() else { continue };
        let Some(_inode) = ws.next() else { continue };
        let Some(path) = ws.next() else { continue };

        if !path.starts_with("/dev/__properties__/") {
            continue;
        }

        let Some((start_s, end_s)) = range.split_once('-') else {
            continue;
        };
        let Ok(start) = usize::from_str_radix(start_s, 16) else {
            continue;
        };
        let Ok(end) = usize::from_str_radix(end_s, 16) else {
            continue;
        };
        let Ok(offset) = u64::from_str_radix(off_str, 16) else {
            continue;
        };

        result.push(PropAreaMapping {
            start,
            end,
            path: path.to_string(),
            offset,
        });
    }
    result
}

// ── COW remap ──────────────────────────────────────────────────────────────

/// 确保 `prop_ptr` 所在的 `/dev/__properties__/*` 映射已被 COW remap。
fn ensure_prop_area_private(
    prop_ptr: *const u8,
    mappings: &[PropAreaMapping],
) -> anyhow::Result<()> {
    let addr = prop_ptr as usize;

    // 缓存命中检查
    let cached = COW_RANGES.with(|r| {
        r.borrow()
            .iter()
            .any(|range| addr >= range.start && addr < range.end)
    });
    if cached {
        return Ok(());
    }

    // 找到包含 prop_ptr 的映射
    let mapping = mappings
        .iter()
        .find(|m| addr >= m.start && addr < m.end)
        .ok_or_else(|| {
            anyhow::anyhow!("prop_info at {addr:#x} not in any /dev/__properties__ mapping")
        })?;

    let size = mapping.end - mapping.start;

    let cpath = std::ffi::CString::new(mapping.path.as_str())
        .map_err(|_| anyhow::anyhow!("invalid path: {path}", path = mapping.path))?;
    let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        anyhow::bail!(
            "open({path}): {err}",
            path = mapping.path,
            err = std::io::Error::last_os_error()
        );
    }

    let ret = unsafe {
        libc::mmap(
            mapping.start as *mut libc::c_void,
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_FIXED,
            fd,
            mapping.offset as libc::off_t,
        )
    };
    unsafe { libc::close(fd) };

    if ret == libc::MAP_FAILED {
        anyhow::bail!(
            "mmap COW remap failed for {path}: {err}",
            path = mapping.path,
            err = std::io::Error::last_os_error()
        );
    }

    COW_RANGES.with(|r| {
        r.borrow_mut().push(PropRange {
            start: mapping.start,
            end: mapping.end,
        });
    });

    info!(
        "COW remapped {path} [{start:#x}-{end:#x}]",
        path = mapping.path,
        start = mapping.start,
        end = mapping.end
    );
    Ok(())
}

// ── Serial area COW ──────────────────────────────────────────────────────

/// 找到 `properties_serial` mapping 并 COW remap，构造 `MmapPropArea`。
///
/// `MmapPropArea::update()` 需要 `serial_pa` 来 bump global area serial + futex wake。
/// COW-remap 后 bump 只影响当前进程的私有副本，不会错误通知其他进程。
fn cow_serial_area(
    mappings: &[PropAreaMapping],
) -> anyhow::Result<std::mem::ManuallyDrop<MmapPropArea>> {
    use memmap2::MmapMut;

    let serial_mapping = mappings
        .iter()
        .find(|m| m.path.ends_with("/properties_serial"))
        .ok_or_else(|| anyhow::anyhow!("properties_serial mapping not found"))?;

    ensure_prop_area_private(serial_mapping.start as *const u8, mappings)?;

    let size = serial_mapping.end - serial_mapping.start;
    let ptr = serial_mapping.start as *mut u8;
    let mmap_mut = unsafe { std::mem::transmute::<(*mut u8, usize), MmapMut>((ptr, size)) };
    let area = MmapPropArea::new(mmap_mut)?;
    Ok(std::mem::ManuallyDrop::new(area))
}

// ── 新增属性：COW trie 插入 ───────────────────────────────────────────────

/// SIBLING_PROBES：sys_prop 不可用时的降级定位手段，用已有属性按前缀猜测 area。
/// 不能作为主路径：猜测结果与 property_contexts 的真实路由经常不一致。
const SIBLING_PROBES: &[(&str, &[&str])] = &[
    (
        "ro.product",
        &["ro.product.model", "ro.product.device", "ro.product.brand"],
    ),
    ("ro.build", &["ro.build.display.id", "ro.build.fingerprint"]),
    ("ro.vendor", &["ro.vendor.build.fingerprint"]),
    ("ro.hardware", &["ro.hardware"]),
    ("persist", &["persist.sys.timezone"]),
    ("ro", &["ro.build.id", "ro.product.model"]),
];

/// sys_prop 一次性初始化（幂等，返回是否可用）。
fn sys_prop_available() -> bool {
    static OK: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *OK.get_or_init(|| {
        if let Err(e) = prop_rs_android::sys_prop::init() {
            warn!("sys_prop::init failed: {e}, context-routed insert disabled");
            false
        } else {
            true
        }
    })
}

/// 按 property context 路由解析新属性的目标 prop_area 路径。
///
/// bionic 的属性读取（`SystemProperties.get` / `__system_property_find`）按
/// property_contexts 规则将 key 路由到特定 context 的 area，新属性必须插入
/// 路由目标 area 才能被读到。SIBLING_PROBES 按前缀猜测的 area 与真实路由
/// 经常不一致（如 `ro.product.odm.*` exact 规则路由到 build_odm_prop 而
/// sibling 探测返回 build_prop；无匹配规则的 key 落到 default_prop）。
fn context_area_path(key: &str) -> Option<String> {
    if !sys_prop_available() {
        return None;
    }
    match prop_rs_android::sys_prop::area_path(key) {
        Ok(path) => {
            let path = path.to_string_lossy().into_owned();
            if path.starts_with("/dev/__properties__/") {
                Some(path)
            } else {
                None
            }
        }
        Err(e) => {
            info!("context area lookup failed for '{key}': {e}");
            None
        }
    }
}

/// 尝试在 COW-remapped 的 prop_area 中为不存在的属性插入新 trie 节点。
///
/// 目标 area 优先按 property context 路由解析（与 bionic 读取路径一致），
/// 仅插入路由目标 area；sys_prop 不可用时降级为 SIBLING_PROBES 前缀探测。
fn cow_patch_new(
    key: &str,
    value: &str,
    mappings: &[PropAreaMapping],
    _find_fn: FnSystemPropertyFind,
) -> anyhow::Result<bool> {
    use memmap2::MmapMut;

    let key_prefix = match key.rfind('.') {
        Some(end) => &key[..end],
        None => key,
    };

    // 1. context 路由优先：只插入 bionic 读取时实际查询的 area。
    //    路由目标 area 未映射在本进程时放弃插入（交给 companion 兜底），
    //    避免插错 area 造成“插入成功但读取不可见”。
    let target_paths: Vec<String> = if let Some(path) = context_area_path(key) {
        if mappings.iter().any(|m| m.path == path) {
            vec![path]
        } else {
            info!("COW trie: context area {path} for '{key}' not mapped, leaving to companion");
            return Ok(false);
        }
    } else {
        // 2. sys_prop 不可用的降级路径：检查 prefix → area 路径缓存
        let cached_paths = PREFIX_AREA_CACHE.with(|c| c.borrow().get(key_prefix).cloned());

        if let Some(paths) = cached_paths {
            // 缓存命中
            paths
        } else {
            // 3. 缓存未命中，遍历 build 相关 area 用 MmapPropArea::find 找包含 sibling 的 area
            let probes: &[&str] = SIBLING_PROBES
                .iter()
                .find(|(pfx, _)| key_prefix == *pfx || key_prefix.starts_with(&format!("{pfx}.")))
                .map(|(_, p)| *p)
                .unwrap_or(&["ro.product.model", "ro.build.id"]);

            let mut found_paths = Vec::new();
            for mapping in mappings {
                if !mapping.path.starts_with("/dev/__properties__/") {
                    continue;
                }
                if !mapping.path.contains("build_prop")
                    && !mapping.path.contains("build_odm_prop")
                    && !mapping.path.contains("build_vendor_prop")
                    && !mapping.path.contains("default_prop")
                {
                    continue;
                }
                let size = mapping.end - mapping.start;
                if size < 128 {
                    continue;
                }
                if ensure_prop_area_private(mapping.start as *const u8, mappings).is_err() {
                    continue;
                }
                let ptr = mapping.start as *mut u8;
                let mmap_mut =
                    unsafe { std::mem::transmute::<(*mut u8, usize), MmapMut>((ptr, size)) };
                let mut area = match MmapPropArea::new(mmap_mut) {
                    Ok(a) => std::mem::ManuallyDrop::new(a),
                    Err(_) => continue,
                };
                let has_sibling = probes.iter().any(|p| matches!(area.find(p), Ok(Some(_))));
                if has_sibling {
                    found_paths.push(mapping.path.clone());
                }
            }
            PREFIX_AREA_CACHE.with(|c| {
                c.borrow_mut()
                    .insert(key_prefix.to_string(), found_paths.clone());
            });
            found_paths
        }
    };

    if target_paths.is_empty() {
        return Ok(false);
    }

    // 在所有匹配的 area 里 emplace（确保 bionic 无论读哪个 area 都能拿到）
    let mut any_inserted = false;
    for path in &target_paths {
        let mapping = match mappings.iter().find(|m| &m.path == path) {
            Some(m) => m,
            None => continue,
        };

        if ensure_prop_area_private(mapping.start as *const u8, mappings).is_err() {
            continue;
        }

        let size = mapping.end - mapping.start;
        let ptr = mapping.start as *mut u8;
        let mmap_mut = unsafe { std::mem::transmute::<(*mut u8, usize), MmapMut>((ptr, size)) };
        let mut area = match MmapPropArea::new(mmap_mut) {
            Ok(a) => std::mem::ManuallyDrop::new(a),
            Err(_) => continue,
        };

        if let Ok(Some(_)) = area.find(key) {
            continue;
        }

        match area.emplace(key, value.as_bytes(), 0) {
            Ok(()) => {
                if let Ok(Some(data_off)) = area.find(key) {
                    let serial = area.read_serial(data_off);
                    // long prop 的 serial 长度字段是固定 legacy 值
                    // （LONG_LEGACY_ERROR），只验证 long 标志；inline prop
                    // 验证长度字段与值一致。
                    let verified = if serial & PROP_INFO_LONG_FLAG != 0 {
                        value.len() >= PROP_VALUE_MAX
                    } else {
                        (serial >> 24) as usize == value.len()
                    };
                    if verified {
                        info!(
                            "COW trie: inserted '{key}' (serial_ok, len={}) into {}",
                            value.len(),
                            mapping.path
                        );
                        any_inserted = true;
                    }
                }
            }
            Err(e) => {
                warn!(
                    "COW trie: emplace failed for '{key}' in {}: {e}",
                    mapping.path
                );
            }
        }
    }

    Ok(any_inserted)
}
