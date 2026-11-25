//! SimpleX Chat protocol subset: JSON content messages over SMP agent A_MSG.
//!
//! Envelope (spec/simplex-chat.md): the agent message body is a JSON object
//!   { "type": "x.msg.new", "params": { "msgId": ..., "content": { "type": "text", "text": ... } } }
//! Profile exchange: { "type": "x.info", "params": { "profile": {...} } }.
//! This is the layer external tools (REA, craft-anything) can speak over an SMP agent connection.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::agent::{Agent, AgentMsg};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextContent {
    #[serde(rename = "type")]
    pub ctype: String, // "text"
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsgParams {
    #[serde(rename = "msgId", skip_serializing_if = "Option::is_none")]
    pub msg_id: Option<String>,
    pub content: TextContent,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quote: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMsg {
    #[serde(rename = "type")]
    pub mtype: String, // "x.msg.new" | "x.info" | ...
    pub params: Value,
}

pub fn encode_chat(cm: &ChatMsg) -> Result<Vec<u8>, String> {
    serde_json::to_vec(cm).map_err(|e| e.to_string())
}

pub fn parse_chat(body: &[u8]) -> Result<ChatMsg, String> {
    serde_json::from_slice(body).map_err(|e| format!("chat json: {e}"))
}

/// Send a text chat message; returns the client-side msgId used.
pub fn send_text(a: &mut Agent, text: &str) -> Result<String, String> {
    let msg_id = format!("{}", a.msg_counter + 1);
    let cm = ChatMsg {
        mtype: "x.msg.new".into(),
        params: serde_json::to_value(MsgParams {
            msg_id: Some(msg_id.clone()),
            content: TextContent { ctype: "text".into(), text: text.into() },
            file: None,
            quote: None,
        })
        .map_err(|e| e.to_string())?,
    };
    a.send_msg(&encode_chat(&cm)?)?;
    Ok(msg_id)
}

/// Receive next chat message (skips non-chat agent messages like HELLO/A_RCVD and non-MSG blocks).
pub fn recv_text(a: &mut Agent) -> Result<(String, String), String> {
    // Built on Agent::recv_agent (audit #3, U-12/H6): the old copy-pasted loop ACKed
    // the broker message BEFORE ratchet decryption (any decrypt error = message lost
    // forever) and returned on the first MSG of a block (the rest were dropped).
    // recv_agent ACKs only after successful decode and keeps every message.
    loop {
        let (_broker_msg_id, am) = a.recv_agent()?;
        if let AgentMsg::Msg { body, .. } = &am {
            let _ = a.flush_outbox();
            let cm = parse_chat(body)?;
            if cm.mtype == "x.msg.new" {
                let params: MsgParams = serde_json::from_value(cm.params).map_err(|e| e.to_string())?;
                return Ok((params.msg_id.unwrap_or_default(), params.content.text));
            }
        }
    }
}

/// Send profile info (x.info) — exchanged during/after handshake.
pub fn send_info(a: &mut Agent, profile_name: &str) -> Result<(), String> {
    let cm = ChatMsg {
        mtype: "x.info".into(),
        params: serde_json::json!({ "profile": { "profileId": "", "localAlias": "", "name": profile_name } }),
    };
    a.send_msg(&encode_chat(&cm)?)?;
    Ok(())
}
