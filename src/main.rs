#![allow(non_snake_case)]

use config::Config;
use serde::Deserialize;

use regex::Regex;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use windows::{
    Win32::Foundation::{GetLastError, LRESULT},
    Win32::System::LibraryLoader::GetModuleHandleW,
    Win32::UI::WindowsAndMessaging::{
        CallNextHookEx, GetMessageW, SetWindowsHookExW, UnhookWindowsHookEx, HC_ACTION, HHOOK,
        KBDLLHOOKSTRUCT, MSG, WH_KEYBOARD_LL, WM_KEYDOWN,
    },
};

const CONFIG_FILE: &str = "config/config.toml";

lazy_static::lazy_static! {
    static ref CONFIG: MonitorConfig = load_config(CONFIG_FILE);
    static ref DIGIT_PATTERN: Regex = Regex::new(&CONFIG.regex.unwrap()).unwrap();
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
    logs_day: Option<u32>,       // 日志保存天数
    time_threshold: Option<u32>, // 时间阈值, ms
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

unsafe extern "system" fn keyboard_proc(n_code: i32, w_param: usize, l_param: isize) -> LRESULT {
    if n_code == HC_ACTION {
        let kb_struct = *(l_param as *const KBDLLHOOKSTRUCT);
        if w_param as u32 == WM_KEYDOWN {
            let vk_code = kb_struct.vkCode as u8 as char;
            if vk_code.is_digit(10) {
                let mut input_state = INPUT_STATE.lock().unwrap();
                if !input_state.timer_started {
                    input_state.start_time = Instant::now();
                    input_state.timer_started = true;
                }
                input_state.buffer.push(vk_code);

                // If the buffer exceeds 10 characters, truncate it from the left (oldest entries)
                if input_state.buffer.len() > 10 {
                    input_state.buffer.remove(0);
                }

                // Check if the current buffer matches the regex pattern and the time is within 5 seconds
                if DIGIT_PATTERN.is_match(&input_state.buffer)
                    && input_state.start_time.elapsed() <= Duration::from_secs(5)
                {
                    println!("{}", input_state.buffer);
                    input_state.buffer.clear();
                    input_state.timer_started = false;
                } else if input_state.start_time.elapsed() > Duration::from_secs(5) {
                    // Reset if time exceeded 5 seconds
                    input_state.buffer.clear();
                    input_state.timer_started = false;
                }
            }
        }
    }

    // Call the next hook in the hook chain
    CallNextHookEx(HHOOK(0), n_code, w_param, l_param)
}

fn main() -> windows::core::Result<()> {
    unsafe {
        let h_instance = GetModuleHandleW(None);
        let hook_id = SetWindowsHookExW(WH_KEYBOARD_LL, Some(keyboard_proc), h_instance, 0);

        if hook_id.is_null() {
            eprintln!("Failed to install hook: {:?}", GetLastError());
            return Err(windows::core::Error::from_win32());
        }

        let mut msg: MSG = MSG::default();
        while GetMessageW(&mut msg, 0, 0, 0).into() {
            // Block here until a message is received
        }

        UnhookWindowsHookEx(hook_id);
    }

    Ok(())
}
