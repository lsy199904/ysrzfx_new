from pathlib import Path


OUTPUT_FILE = Path(__file__).with_name("eventsource_sse_client_template.txt")


TEMPLATE = r'''原生 EventSource SSE 客户端模板
================================

说明：
- 当前 /agentchat 是 POST + SSE 接口，应使用下面的 PostSSEClient。
- 不预设模型输出字段，模型返回什么字段就原样交给 onMessage。
- 中文问题和英文问题入口已分别预留。


一、POST + SSE 版本
===================

class PostSSEClient {
  constructor(url, options = {}) {
    this.url = url;
    this.options = {
      onMessage: () => {},
      onError: () => {},
      onComplete: () => {},
      ...options,
    };
    this.controller = null;
  }

  async connect(payload) {
    this.close();
    this.controller = new AbortController();

    try {
      const response = await fetch(this.url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Accept": "text/event-stream",
        },
        body: JSON.stringify(payload),
        signal: this.controller.signal,
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      if (!response.body) {
        throw new Error("浏览器不支持流式响应");
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder("utf-8");
      let buffer = "";

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const events = buffer.split(/\r?\n\r?\n/);
        buffer = events.pop() || "";

        for (const eventText of events) {
          this.handleEvent(eventText);
        }
      }

      buffer += decoder.decode();
      if (buffer.trim()) {
        this.handleEvent(buffer);
      }

      this.options.onComplete();
    } catch (error) {
      if (error.name !== "AbortError") {
        this.options.onError(error);
      }
    }
  }

  handleEvent(eventText) {
    const dataLines = eventText
      .split(/\r?\n/)
      .filter((line) => line.startsWith("data:"))
      .map((line) => line.slice(5).trimStart());

    if (dataLines.length === 0) return;

    const dataText = dataLines.join("\n").trim();
    if (!dataText || dataText === "[DONE]") return;

    let data;
    try {
      data = JSON.parse(dataText);
    } catch (error) {
      data = dataText;
    }

    // 不判断字段名称，由调用方自行处理模型输出。
    this.options.onMessage(data, dataText);
  }

  close() {
    if (this.controller) {
      this.controller.abort();
      this.controller = null;
    }
  }
}


二、中文和英文问题调用入口
============================

const sseClient = new PostSSEClient("http://你的服务地址:5050/agentchat", {
  onMessage(data, rawText) {
    // data 可能是任意 JSON 对象，也可能是普通文本。
    console.log("模型流式数据：", data);
  },

  onError(error) {
    console.error("SSE 请求失败：", error);
  },

  onComplete() {
    console.log("SSE 流结束");
  },
});

function askChinese() {
  const chineseQuestion = "这里填写你的中文问题";

  sseClient.connect({
    session_id: "前端会话 ID",
    user_input: chineseQuestion,
    login_account: "登录账号",
    is_admin: false,
    allowed_gids: ["12345", "19936", "65789"],
  });
}

function askEnglish() {
  const englishQuestion = "Put your English question here";

  sseClient.connect({
    session_id: "前端会话 ID",
    user_input: englishQuestion,
    login_account: "登录账号",
    is_admin: false,
    allowed_gids: ["12345", "19936", "65789"],
  });
}


三、如果后端提供 GET SSE 接口，才使用原生 EventSource
========================================================

class EventSourceClient {
  constructor(url, options = {}) {
    this.url = url;
    this.options = {
      onMessage: () => {},
      onError: () => {},
      onOpen: () => {},
      ...options,
    };
    this.source = null;
  }

  connect() {
    this.close();
    this.source = new EventSource(this.url);

    this.source.onopen = () => this.options.onOpen();

    this.source.onmessage = (event) => {
      const rawText = event.data;
      let data;

      try {
        data = JSON.parse(rawText);
      } catch (error) {
        data = rawText;
      }

      // event.data 已经去掉了 data: 前缀。
      this.options.onMessage(data, rawText);
    };

    this.source.onerror = (error) => this.options.onError(error);
  }

  close() {
    if (this.source) {
      this.source.close();
      this.source = null;
    }
  }
}
'''


def main() -> None:
    OUTPUT_FILE.write_text(TEMPLATE, encoding="utf-8")
    print(f"已生成：{OUTPUT_FILE}")


if __name__ == "__main__":
    main()
