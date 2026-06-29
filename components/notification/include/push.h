#pragma once

#include "config.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"

// 绑定 sms_notify 任务队列（须在 app_main 早期调用）
void push_set_notify_queue(QueueHandle_t queue);

// 异步提交推送（入队后由 sms_notify 大栈任务执行，避免 main/httpd 栈溢出）
bool push_submit_to_all(const char *sender, const char *message, const char *timestamp);
bool push_submit_to_channel(int channel_index, const char *sender, const char *message,
                            const char *timestamp);

// 发送到指定推送通道（同步，仅应在 sms_notify 等大栈任务中调用）
void push_send_to_channel(const push_channel_t *channel,
                           const char *sender, const char *message,
                           const char *timestamp);

// 发送到所有启用的推送通道（同步，仅应在 sms_notify 等大栈任务中调用）
void push_send_to_all(const char *sender, const char *message,
                       const char *timestamp);
