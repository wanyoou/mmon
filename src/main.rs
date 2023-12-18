#![allow(non_snake_case)]

use config::Config;
use serde::Deserialize;

use log::{error, info, warn};
use log4rs;
use regex::Regex;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use std::collections::VecDeque;
use windows::{
    Win32::Foundation::{GetLastError, HWND, LPARAM, LRESULT, WPARAM},
    Win32::System::LibraryLoader::GetModuleHandleW,
    Win32::UI::WindowsAndMessaging::{
        CallNextHookEx, GetMessageW, SetWindowsHookExW, UnhookWindowsHookEx, HC_ACTION, HHOOK,
        KBDLLHOOKSTRUCT, MSG, WH_KEYBOARD_LL, WM_KEYDOWN,
    },
};

/* 
use std::collections::VecDeque;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;

fn main() {
    // Create a channel for sending String values
    let (tx, rx): (Sender<String>, Receiver<String>) = mpsc::channel();

    // Spawn the consumer thread
    thread::spawn(move || {
        while let Ok(value) = rx.recv() {
            // Print the value received from the main thread
            println!("Consumed: {}", value);
        }
    });

    // The main thread will act as the producer
    let mut vqueue: VecDeque<String> = VecDeque::new();

    // Simulate adding items to the queue
    for i in 0..5 {
        let value = format!("Item {}", i);
        vqueue.push_back(value.clone());
        // Send the value to the consumer thread
        tx.send(value).unwrap();

        // Sleep to simulate work
        thread::sleep(std::time::Duration::from_secs(1));
    }
}
*/

const CONFIG_FILE: &str = "config/config.toml";
const LOG_CONFIG_FILE: &str = "config/log4rs.yaml";

lazy_static::lazy_static! {
    static ref CONFIG: MonitorConfig = load_config(CONFIG_FILE);
    static ref DIGIT_PATTERN: Regex = Regex::new(&CONFIG.regex.clone().unwrap()).unwrap();
    static ref INPUT_STATE: Mutex<InputState> = Mutex::new(InputState {
        buffer: String::new(),
        start_time: Instant::now(),
        timer_started: false,
    });
}

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
            let time_threshold = Duration::from_millis(CONFIG.time_threshold.unwrap());
            if DIGIT_PATTERN.is_match(&input_state.buffer) && elapse <= time_threshold {
                info!("检测到有效的扫码枪输入: {}", input_state.buffer);
                input_state.buffer.clear();
                input_state.timer_started = false;
            } else if elapse > time_threshold {
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

fn my_log_init() {
    log4rs::init_file(LOG_CONFIG_FILE, Default::default()).unwrap();
    info!("Barcode Scanner Monitor 程序初始化");
    info!("客户端序列号: {}", CONFIG.client_sn.clone().unwrap());
    info!("监控模式: {:?}", CONFIG.mode.clone().unwrap());
    info!("正则表达式: {}", CONFIG.regex.clone().unwrap());
    info!("扫码枪时间阈值: {}ms", CONFIG.time_threshold.unwrap());
    info!("后台接口地址: {}", CONFIG.server_url.clone().unwrap());
    info!("程序初始化完成");
}

fn main() -> windows::core::Result<()> {
    my_log_init();

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
