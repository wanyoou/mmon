#![allow(non_snake_case)]
#![windows_subsystem = "windows"]

use config::Config;
use log::{error, info};
use log4rs;
use regex::Regex;
use reqwest::blocking::Client;
use serde::Deserialize;
use std::collections::VecDeque;
use std::sync::{
    mpsc::{self, Receiver, Sender},
    Mutex,
};
use std::thread;
use std::time::{Duration, Instant};
use windows::{
    core::*,
    Win32::Foundation::*,
    Win32::System::LibraryLoader::GetModuleHandleA,
    Win32::UI::Shell::*,
    Win32::UI::WindowsAndMessaging::{
        self, AppendMenuA, CallNextHookEx, CreatePopupMenu, DestroyMenu, GetMessageA,
        PostQuitMessage, RegisterClassA, SetForegroundWindow, SetWindowsHookExA, TrackPopupMenu,
        UnhookWindowsHookEx, HC_ACTION, HHOOK, IMAGE_CURSOR, IMAGE_ICON, KBDLLHOOKSTRUCT,
        LR_DEFAULTSIZE, LR_LOADFROMFILE, LR_SHARED, MSG, WH_KEYBOARD_LL, WM_APP, WM_COMMAND,
        WM_DESTROY, WM_KEYDOWN, WM_RBUTTONUP, WNDCLASSA,
    },
};

const CONFIG_FILE: &str = "config/config.toml";
const LOG_CONFIG_FILE: &str = "config/log4rs.yaml";

// 需以\0结尾
const TRAY_ICON_FILE: &str = "resource/barcode.ico\0";
const TRAY_ICON_TOOLTIP: &str = "ClearScannerMonitor\0";

const WM_TRAYICON: u32 = WM_APP + 1;
const ID_TRAY_APP: u32 = 1001;
const ID_EXIT: u32 = 2001;

lazy_static::lazy_static! {
    static ref CONFIG: MonitorConfig = MonitorConfig::new(CONFIG_FILE);
    static ref TIME_THRESHOLD_RAW: u64 = CONFIG.time_threshold.unwrap();
    static ref TIME_THRESHOLD: Duration = Duration::from_millis(*TIME_THRESHOLD_RAW);
    static ref CLIENT_SN: String = CONFIG.client_sn.clone().unwrap();
    static ref SERVER_URL: String = CONFIG.server_url.clone().unwrap();
    static ref REGEX_RAW: String = CONFIG.regex.clone().unwrap();
    static ref REGEX_PATTERN: Regex = Regex::new((*REGEX_RAW).as_str()).unwrap();
    static ref MODE: MonitorMode = CONFIG.mode.clone().unwrap();
    static ref INPUT_STATE: Mutex<VecDeque<InputState>> = Mutex::new(VecDeque::with_capacity(20));
}
static mut TX: Option<&mut Sender<String>> = None;

struct InputState {
    buffer: String,
    start_time: Instant,
}

#[derive(Deserialize, Clone, Debug)]
enum MonitorMode {
    Block,       // 屏蔽
    Passthrough, // 透传
}

#[derive(Deserialize, Clone, Debug)]
struct MonitorConfig {
    server_url: Option<String>,  // 后台接口地址
    regex: Option<String>,       // 匹配正则
    client_sn: Option<String>,   // 客户端序列号
    time_threshold: Option<u64>, // 时间阈值, ms
    mode: Option<MonitorMode>,   // 监控模式
}

impl MonitorConfig {
    fn new(path: &str) -> MonitorConfig {
        Config::builder()
            .add_source(config::File::with_name(path))
            .build()
            .unwrap()
            .try_deserialize::<MonitorConfig>()
            .expect("Failed to load config")
    }
}

/**
 * 每触发一次击键事件，就依次检查已经存在的实例是否超时。
 * 如果实例超时，就删除超时实例；否则更新实例 buffer，同时检查是否可以成功匹配。
 * 如果有实例成功匹配，就清空实例队列，删除所有实例；否则新创建一个 InputState 实例。
 */
unsafe extern "system" fn keyboard_proc(n_code: i32, w_param: WPARAM, l_param: LPARAM) -> LRESULT {
    // 记录此次击键时刻
    let now = Instant::now();

    if (n_code as u32 == HC_ACTION) && (w_param.0 as u32 == WM_KEYDOWN) {
        let kb_struct = *(l_param.0 as *const KBDLLHOOKSTRUCT);
        let key = kb_struct.vkCode as u8 as char;
        let mut input_state = INPUT_STATE.lock().unwrap();

        // 是否已经创建了新实例
        let mut new_instance = false;
        if input_state.is_empty() {
            input_state.push_back(InputState {
                buffer: String::new(),
                start_time: now,
            });
            new_instance = true;
        }

        // 超时实例计数
        let mut timeout_count = 0;
        let mut match_success = false;
        for input in input_state.iter_mut() {
            if now.duration_since(input.start_time) > *TIME_THRESHOLD {
                timeout_count += 1;
            } else {
                input.buffer.push(key);
                if REGEX_PATTERN.is_match(&input.buffer) {
                    let input_valid = input.buffer.trim_end();
                    info!("检测到有效的扫码枪输入: {}", input_valid);
                    TX.as_ref().unwrap().send(input_valid.to_string()).unwrap();
                    match_success = true;
                    break;
                }
            }
        }

        if match_success {
            input_state.clear();
        } else if !new_instance {
            // 新创建一个实例，排除第一个实例刚刚创建过的情况
            input_state.push_back(InputState {
                buffer: key.to_string(),
                start_time: now,
            })
        }

        // 删除超时实例
        if !match_success && timeout_count > 0 {
            while timeout_count > 0 {
                input_state.pop_front();
                timeout_count -= 1;
            }
        }
    }

    if let MonitorMode::Passthrough = *MODE {
        CallNextHookEx(HHOOK(0), n_code, w_param, l_param)
    } else {
        LRESULT(0)
    }
}

// 托盘图标事件处理
unsafe extern "system" fn window_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_TRAYICON => {
            if lparam.0 as u32 == WM_RBUTTONUP {
                let mut point = POINT::default();
                if let Ok(()) = WindowsAndMessaging::GetCursorPos(&mut point) {
                    let hmenu = CreatePopupMenu().unwrap();
                    AppendMenuA(
                        hmenu,
                        WindowsAndMessaging::MF_STRING,
                        ID_EXIT as usize,
                        PCSTR(b"Exit\0".as_ptr()),
                    )
                    .unwrap();

                    SetForegroundWindow(hwnd);
                    TrackPopupMenu(
                        hmenu,
                        WindowsAndMessaging::TPM_BOTTOMALIGN,
                        point.x,
                        point.y,
                        0,
                        hwnd,
                        Some(std::ptr::null()),
                    );
                    DestroyMenu(hmenu).unwrap();
                }
            }
        }
        WM_COMMAND => {
            let menu_id = wparam.0 as u32;
            match menu_id {
                ID_EXIT => {
                    PostQuitMessage(0);
                }
                _ => {}
            }
        }
        WM_DESTROY => {
            PostQuitMessage(0);
        }
        _ => return WindowsAndMessaging::DefWindowProcA(hwnd, msg, wparam, lparam),
    }
    LRESULT(0)
}

fn load_icon_from_file() -> windows::core::Result<WindowsAndMessaging::HICON> {
    let hicon_handle = unsafe {
        WindowsAndMessaging::LoadImageA(
            None,
            PCSTR(TRAY_ICON_FILE.as_bytes().as_ptr()),
            IMAGE_ICON,
            0,
            0,
            LR_LOADFROMFILE,
        )?
    };
    if hicon_handle.is_invalid() {
        Err(windows::core::Error::from_win32())
    } else {
        Ok(WindowsAndMessaging::HICON(hicon_handle.0))
    }
}

fn log_init() {
    log4rs::init_file(LOG_CONFIG_FILE, Default::default()).unwrap();
    info!("Barcode Scanner Monitor 程序初始化");
    info!("客户端序列号: {}", *CLIENT_SN);
    info!("监控模式: {:?}", *MODE);
    info!("正则表达式: {}", *REGEX_RAW);
    info!("扫码枪时间阈值: {}ms", *TIME_THRESHOLD_RAW);
    info!("后台接口地址: {}", *SERVER_URL);
    info!("Barcode Scanner Monitor 程序初始化完成");
}

fn main() -> windows::core::Result<()> {
    log_init();

    let (tx, rx): (Sender<String>, Receiver<String>) = mpsc::channel();
    unsafe {
        TX = Some(Box::leak(Box::new(tx)));
    }

    thread::spawn(move || -> reqwest::Result<()> {
        let mut req;
        let mut res;
        let client = Client::new();
        while let Ok(value) = rx.recv() {
            req = client
                .get((*SERVER_URL).as_str())
                .query(&[("code", value.as_str()), ("sn", (*CLIENT_SN).as_str())])
                .timeout(Duration::from_secs(3))
                .build()?;
            info!("GET Request: {}", req.url());

            res = client.execute(req)?;
            if res.status().is_success() {
                info!("GET Response: {}", res.text()?);
            } else {
                error!("GET Response Error. Status: {:?}", res.status());
            }
        }
        Ok(())
    });

    unsafe {
        let h_instance = GetModuleHandleA(None)?;
        let hook_id = SetWindowsHookExA(WH_KEYBOARD_LL, Some(keyboard_proc), h_instance, 0)?;

        if hook_id.is_invalid() {
            error!("Failed to install hook: {:?}", GetLastError());
            return Err(windows::core::Error::from_win32());
        }

        /* 托盘图标逻辑 */
        let wnd_class = WNDCLASSA {
            hCursor: WindowsAndMessaging::HCURSOR(
                WindowsAndMessaging::LoadImageW(
                    None,
                    WindowsAndMessaging::IDC_ARROW,
                    IMAGE_CURSOR,
                    0,
                    0,
                    LR_DEFAULTSIZE | LR_SHARED,
                )?
                .0,
            ),
            hInstance: h_instance.into(),
            lpszClassName: PCSTR(b"tray_window\0".as_ptr()),
            lpfnWndProc: Some(window_proc),
            ..Default::default()
        };

        RegisterClassA(&wnd_class);

        let hwnd = WindowsAndMessaging::CreateWindowExA(
            Default::default(),
            PCSTR(b"tray_window\0".as_ptr()),
            PCSTR(b"Tray Window\0".as_ptr()),
            WindowsAndMessaging::WS_OVERLAPPEDWINDOW,
            WindowsAndMessaging::CW_USEDEFAULT,
            WindowsAndMessaging::CW_USEDEFAULT,
            WindowsAndMessaging::CW_USEDEFAULT,
            WindowsAndMessaging::CW_USEDEFAULT,
            None,
            None,
            h_instance,
            Some(std::ptr::null()),
        );

        let mut nid = NOTIFYICONDATAA {
            cbSize: std::mem::size_of::<NOTIFYICONDATAA>() as u32,
            hWnd: hwnd,
            uID: ID_TRAY_APP,
            uFlags: NIF_MESSAGE | NIF_ICON | NIF_TIP,
            uCallbackMessage: WM_TRAYICON,
            hIcon: load_icon_from_file()?,
            szTip: {
                let bytes = TRAY_ICON_TOOLTIP.as_bytes();
                let mut array: [u8; 128] = [0; 128];
                array[..bytes.len()].copy_from_slice(bytes);
                array
            },
            ..Default::default()
        };

        Shell_NotifyIconA(NIM_ADD, &mut nid);

        // The thread that installed the hook must have a message loop
        let mut msg: MSG = MSG::default();
        while GetMessageA(&mut msg, HWND(0), 0, 0).into() {
            WindowsAndMessaging::TranslateMessage(&msg);
            WindowsAndMessaging::DispatchMessageA(&msg);
        }

        UnhookWindowsHookEx(hook_id)?;
        Shell_NotifyIconA(NIM_DELETE, &mut nid);
    }

    Ok(())
}
