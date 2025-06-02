import requests
import json
import time
import hmac
import hashlib
import base64
import urllib.parse
from loguru import logger


# 获取当前时间戳和签名
def get_timestamp_and_sign(secret):
    timestamp = str(round(time.time() * 1000))
    secret_enc = secret.encode('utf-8')
    string_to_sign = '{}\n{}'.format(timestamp, secret)
    string_to_sign_enc = string_to_sign.encode('utf-8')
    hmac_code = hmac.new(secret_enc, string_to_sign_enc, digestmod=hashlib.sha256).digest()
    sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
    return timestamp, sign


# 发送钉钉通知
def send_message(webhook_url, secret, content, title="BiliTickerBuy 通知"):
    if not webhook_url or not secret:
        logger.debug("DingTalk webhook_url 或 secret 未配置，跳过发送")
        return

    try:
        timestamp, sign = get_timestamp_and_sign(secret)
        # 确保 access_token 在 URL 中，而不是整个 webhook_url 作为 access_token
        if "?access_token=" not in webhook_url:
            logger.error("DingTalk webhook_url 格式不正确，应包含 ?access_token=")
            return

        final_webhook_url = f'{webhook_url}&timestamp={timestamp}&sign={sign}'

        headers = {
            'Content-Type': 'application/json',
        }
        message = f"{title}\n\n{content}"
        data = {
            'msgtype': 'text',
            'text': {
                'content': message
            }
        }
        response = requests.post(final_webhook_url, headers=headers, data=json.dumps(data), timeout=10)
        if response.status_code == 200 and response.json().get("errcode") == 0:
            logger.info("DingTalk 消息发送成功")
        else:
            logger.error(f"DingTalk 消息发送失败: {response.status_code} - {response.text}")
    except Exception as e:
        logger.error(f"DingTalk 消息发送异常: {e}")
