#![allow(non_snake_case)]

use config::Config;
use serde::Deserialize;

use log::{error, info, warn};
use log4rs;
use regex::Regex;
use reqwest::Client;
use std::sync::{
    mpsc::{self, Receiver, Sender},
    Mutex,
};
use std::thread;
use std::time::{Duration, Instant};
use windows::{
    Win32::Foundation::{GetLastError, HWND, LPARAM, LRESULT, WPARAM},
    Win32::System::LibraryLoader::GetModuleHandleW,
    Win32::UI::WindowsAndMessaging::{
        CallNextHookEx, GetMessageW, SetWindowsHookExW, UnhookWindowsHookEx, HC_ACTION, HHOOK,
        KBDLLHOOKSTRUCT, MSG, WH_KEYBOARD_LL, WM_KEYDOWN,
    },
};

const CONFIG_FILE: &str = "config/config.toml";
const LOG_CONFIG_FILE: &str = "config/log4rs.yaml";

lazy_static::lazy_static! {
    static ref CONFIG: MonitorConfig = load_config(CONFIG_FILE);
    static ref TIME_THRESHOLD_RAW: u64 = CONFIG.time_threshold.unwrap();
    static ref TIME_THRESHOLD: Duration = Duration::from_millis(*TIME_THRESHOLD_RAW);
    static ref CLIENT_SN: String = CONFIG.client_sn.clone().unwrap();
    static ref SERVER_URL: String = CONFIG.server_url.clone().unwrap();
    static ref MODE: MonitorMode = CONFIG.mode.clone().unwrap();
    static ref REGEX_RAW: String = CONFIG.regex.clone().unwrap();
    static ref REGEX_PATTERN: Regex = Regex::new((*REGEX_RAW).as_str()).unwrap();
    static ref INPUT_STATE: Mutex<InputState> = Mutex::new(InputState {
        buffer: String::new(),
        start_time: Instant::now(),
        timer_started: false,
    });
}
static mut TX: Option<&mut Sender<String>> = None;

struct InputState {
    buffer: String,
    start_time: Instant,
    timer_started: bool,
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

fn load_config(path: &str) -> MonitorConfig {
    Config::builder()
        .add_source(config::File::with_name(path))
        .build()
        .unwrap()
        .try_deserialize::<MonitorConfig>()
        .expect("Failed to load config")
}

unsafe extern "system" fn keyboard_proc(n_code: i32, w_param: WPARAM, l_param: LPARAM) -> LRESULT {
    if n_code as u32 == HC_ACTION {
        let kb_struct = *(l_param.0 as *const KBDLLHOOKSTRUCT);

        if w_param.0 as u32 == WM_KEYDOWN {
            let vk_code = kb_struct.vkCode as u8 as char;
            let mut input_state = INPUT_STATE.lock().unwrap();
            if !input_state.timer_started {
                input_state.start_time = Instant::now();
                input_state.timer_started = true;
            }
            input_state.buffer.push(vk_code);

            let elapse = input_state.start_time.elapsed();
            if REGEX_PATTERN.is_match(&input_state.buffer) && elapse <= *TIME_THRESHOLD {
                info!("检测到有效的扫码枪输入: {}", input_state.buffer);
                input_state.buffer.clear();
                input_state.timer_started = false;
            } else if elapse > *TIME_THRESHOLD {
                input_state.buffer.clear();
                input_state.timer_started = false;
            }
        }
    }

    if let MonitorMode::Passthrough = CONFIG.mode.clone().unwrap() {
        CallNextHookEx(HHOOK(0), n_code, w_param, l_param)
    } else {
        LRESULT(0)
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

    thread::spawn(async move || -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new();
        while let Ok(value) = rx.recv() {
            let res = client
                .get(*SERVER_URL)
                .query(&[("code", value), ("sn", *CLIENT_SN)])
                .await?
                .text()
                .await?;
            info!("Response: {}", res);
        }
        Ok(())
    });

    unsafe {
        let h_instance = GetModuleHandleW(None).unwrap();
        let hook_id =
            SetWindowsHookExW(WH_KEYBOARD_LL, Some(keyboard_proc), h_instance, 0).unwrap();

        if hook_id.is_invalid() {
            eprintln!("Failed to install hook: {:?}", GetLastError());
            return Err(windows::core::Error::from_win32());
        }

        let mut msg: MSG = MSG::default();
        while GetMessageW(&mut msg, HWND(0), 0, 0).into() {
            // Block here until a message is received
        }

        let _ = UnhookWindowsHookEx(hook_id);
    }

    Ok(())
}
