import json
import os
import re
import shutil
from datetime import datetime
from typing import Any, Dict, List
from urllib.parse import urlparse, parse_qs

import gradio as gr
from gradio_calendar import Calendar
from loguru import logger

from util.BiliRequest import BiliRequest
from util import TEMP_PATH, GLOBAL_COOKIE_PATH, main_request, set_main_request

buyer_value: List[Dict[str, Any]] = []
addr_value: List[Dict[str, Any]] = []
ticket_value: List[Dict[str, Any]] = []
project_name: str = ""
ticket_str_list: List[str] = []
sales_dates = []
project_id = 0

sales_flag_number_map = {
    1: "不可售",
    2: "预售",
    3: "停售",
    4: "售罄",
    5: "不可用",
    6: "库存紧张",
    8: "暂时售罄",
    9: "不在白名单",
    101: "未开始",
    102: "已结束",
    103: "未完成",
    105: "下架",
    106: "已取消",
}


def filename_filter(filename):
    filename = re.sub('[/:*?"<>|]', "", filename)
    return filename


def on_submit_ticket_id(num):
    global buyer_value
    global addr_value
    global ticket_value
    global project_name
    global ticket_str_list
    global sales_dates
    global project_id
    try:
        buyer_value = []
        addr_value = []
        ticket_value = []
        extracted_id_message = ""
        if "http" in num or "https" in num:
            num = extract_id_from_url(num)
            extracted_id_message = f"已提取URL票ID：{num}"
        else:
            raise gr.Error("输入无效，请输入一个有效的网址。", duration=5)
        res = main_request.get(
            url=f"https://show.bilibili.com/api/ticket/project/getV2?version=134&id={num}&project_id={num}"
        )
        ret = res.json()
        # logger.debug(ret)

        # 检查 errno
        if ret.get("errno", ret.get("code")) == 100001:
            raise gr.Error("输入无效，请输入一个有效的网址。", duration=5)
        elif ret.get("errno", ret.get("code")) != 0:
            raise gr.Error(ret.get("msg", "未知错误") + "。", duration=5)
        data = ret["data"]
        ticket_str_list = []

        project_id = data["id"]
        project_name = data["name"]

        project_start_time = datetime.fromtimestamp(data["start_time"]).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        project_end_time = datetime.fromtimestamp(data["end_time"]).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        venue_info = data["venue_info"]
        venue_name = venue_info["name"]
        venue_address = venue_info["address_detail"]
        sales_dates = [t["date"] for t in data["sales_dates"]]
        sales_dates_show = len(data["sales_dates"]) != 0
        for item in data["screen_list"]:
            item["project_id"] = data["id"]
        # 场贩
        good_list = main_request.get(
            url=f"https://show.bilibili.com/api/ticket/linkgoods/list?project_id={project_id}&page_type=0"
        )
        good_list = good_list.json()
        ids = [item["id"] for item in good_list["data"]["list"]]
        for id in ids:
            good_detail = main_request.get(
                url=f"https://show.bilibili.com/api/ticket/linkgoods/detail?link_id={id}"
            )
            good_detail = good_detail.json()
            for item in good_detail["data"]["specs_list"]:
                item["project_id"] = good_detail["data"]["item_id"]
                item["link_id"] = id
            data["screen_list"] += good_detail["data"]["specs_list"]
        for screen in data["screen_list"]:
            screen_name = screen["name"]
            screen_id = screen["id"]
            project_id = screen["project_id"]
            express_fee = 0
            if data["has_eticket"]:
                express_fee = 0  # 电子票免费
            else:
                if screen["express_fee"] >= 0:
                    # -2 === t ? "快递到付" : -1 === t ? "快递包邮" : "快递配送"
                    express_fee = screen["express_fee"]

            for ticket in screen["ticket_list"]:
                ticket_desc = ticket["desc"]
                sale_start = ticket["sale_start"]
                ticket["price"] = ticket_price = ticket["price"] + express_fee
                ticket["screen"] = screen_name
                ticket["screen_id"] = screen_id
                if "link_id" in screen:
                    ticket["link_id"] = screen["link_id"]
                ticket_can_buy = sales_flag_number_map[ticket["sale_flag_number"]]
                ticket_str = f"{screen_name} - {ticket_desc} - ￥{ticket_price / 100}- {ticket_can_buy} - 【起售时间：{sale_start}】"
                ticket_str_list.append(ticket_str)
                ticket_value.append(
                    {"project_id": screen["project_id"], "ticket": ticket}
                )

        buyer_json = main_request.get(
            url=f"https://show.bilibili.com/api/ticket/buyer/list?is_default&projectId={project_id}"
        ).json()
        logger.debug(buyer_json)
        addr_json = main_request.get(
            url="https://show.bilibili.com/api/ticket/addr/list"
        ).json()
        logger.debug(addr_json)
        buyer_value = buyer_json["data"]["list"]
        buyer_str_list = [
            f"{item['name']}-{item['personal_id']}" for item in buyer_value
        ]
        addr_value = addr_json["data"]["addr_list"]
        addr_str_list = [
            f"{item['addr']}-{item['name']}-{item['phone']}" for item in addr_value
        ]

        yield [
            gr.update(choices=ticket_str_list),
            gr.update(choices=buyer_str_list),
            gr.update(choices=buyer_str_list),
            gr.update(choices=addr_str_list),
            gr.update(visible=True),
            gr.update(
                value=f"{extracted_id_message}\n获取票信息成功:\n展会名称：{project_name}\n"
                      f"开展时间：{project_start_time} - {project_end_time}\n场馆地址：{venue_name} {venue_address}",
                visible=True,
            ),
            gr.update(visible=True, value=sales_dates[0])
            if sales_dates_show
            else gr.update(visible=False),
        ]
    except gr.Error as e:
        gr.Warning(e.message)
    except Exception as e:
        logger.exception(e)


def extract_id_from_url(url):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    return query_params.get("id", [None])[0]


def on_submit_all(
        ticket_id,
        ticket_info: int,
        people_indices,
        people_buyer_index,
        address_index,
):
    try:
        ticket_cur: dict[str, Any] = ticket_value[ticket_info]
        people_cur = [buyer_value[item] for item in people_indices]
        people_buyer_cur = buyer_value[people_buyer_index]
        ticket_id = extract_id_from_url(ticket_id)
        if ticket_id is None:
            raise gr.Error("你所填不是网址，或者网址是错的", duration=5)
        if len(people_indices) == 0:
            raise gr.Error("至少选一个实名人", duration=5)
        if addr_value is None:
            raise gr.Error("没有填写地址", duration=5)
        address_cur = addr_value[address_index]
        username = main_request.get_request_name()
        detail = f"{username}-{project_name}-{ticket_str_list[ticket_info]}"
        for p in people_cur:
            detail += f"-{p['name']}"
        config_dir = {
            "username": username,
            "detail": detail,
            "count": len(people_indices),
            "screen_id": ticket_cur["ticket"]["screen_id"],
            "project_id": ticket_cur["project_id"],
            "sku_id": ticket_cur["ticket"]["id"],
            "order_type": 1,
            "pay_money": ticket_cur["ticket"]["price"] * len(people_indices),
            "buyer_info": people_cur,
            "buyer": people_buyer_cur["name"],
            "tel": people_buyer_cur["tel"],
            "deliver_info": {
                "name": address_cur["name"],
                "tel": address_cur["phone"],
                "addr_id": address_cur["id"],
                "addr": address_cur["prov"]
                        + address_cur["city"]
                        + address_cur["area"]
                        + address_cur["addr"],
            },
            "cookies": main_request.cookieManager.get_cookies(),
            "phone": main_request.cookieManager.get_config_value("phone", ""),
        }
        if "link_id" in ticket_cur["ticket"]:
            config_dir["link_id"] = ticket_cur["ticket"]["link_id"]
        filename = os.path.join(TEMP_PATH, filename_filter(detail) + ".json")
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(config_dir, f, ensure_ascii=False, indent=4)
        yield [
            gr.update(value=config_dir, visible=True),
            gr.update(value=filename, visible=True),
        ]
    except gr.Error as e:
        gr.Warning(e.message)
    except Exception:
        raise gr.Error("生成错误，仔细看看你可能有哪里漏填的", duration=5)


def upload_file(filepath):
    try:
        shutil.copy2(filepath, GLOBAL_COOKIE_PATH)  # 修复导入失败的bug
        os.makedirs(os.path.dirname(GLOBAL_COOKIE_PATH), exist_ok=True)
        set_main_request(BiliRequest(cookies_config_path=GLOBAL_COOKIE_PATH))
        name = main_request.get_request_name()
        gr.Info("导入成功", duration=5)
        if name != "未登录" and os.path.exists(GLOBAL_COOKIE_PATH):
            new_cookie_filename = f"{name}_cookies.json"
            os.makedirs(TEMP_PATH, exist_ok=True)
            new_cookie_path = os.path.join(TEMP_PATH, new_cookie_filename)
            shutil.copy2(GLOBAL_COOKIE_PATH, new_cookie_path)
            yield [
                gr.update(value=name),
                gr.update(value=new_cookie_path),
            ]
        else:
            yield [
                gr.update(value=name),
                gr.update(value=GLOBAL_COOKIE_PATH)
            ]
    except Exception as e:
        name = main_request.get_request_name()
        logger.exception(e)
        raise gr.Error("登录出现错误", duration=5)


def add():
    main_request.cookieManager.db.delete("cookie")
    gr.Info("已经注销，将打开浏览器，请在浏览器里面重新登录", duration=5)
    yield [
        gr.update(value="未登录"),
        gr.update(value=GLOBAL_COOKIE_PATH),
    ]
    try:
        main_request.cookieManager.get_cookies_str_force()
        name = main_request.get_request_name()
        gr.Info("登录成功", duration=5)
        if name != "未登录" and os.path.exists(GLOBAL_COOKIE_PATH):
            new_cookie_filename = f"{name}_cookies.json"
            os.makedirs(TEMP_PATH, exist_ok=True)
            new_cookie_path = os.path.join(TEMP_PATH, new_cookie_filename)
            shutil.copy2(GLOBAL_COOKIE_PATH, new_cookie_path)
            yield [
                gr.update(value=name),
                gr.update(value=new_cookie_path),
            ]
        else:
            yield [
                gr.update(value=name),
                gr.update(value=GLOBAL_COOKIE_PATH)
            ]

    except Exception:
        name = main_request.get_request_name()
        raise gr.Error("登录出现错误", duration=5)


def logout():
    try:
        main_request.cookieManager.db.delete("cookie")
        gr.Info("已注销登录,本地cookie已清除", duration=5)
        return "未登录", GLOBAL_COOKIE_PATH
    except Exception as e:
        logger.exception(f"注销时发生错误:{e}")
        gr.Error("注销登录失败，请手动删除cookie文件", duration=5)
        return main_request.get_request_name(), GLOBAL_COOKIE_PATH


def setting_tab():
    gr.Markdown("""
> **必看**
>
> 保证自己在抢票前，已经配置了地址和购买人信息(就算不需要也要提前填写) 如果没填，生成表单时候不会出现任何选项
>
> - 地址 ： 会员购中心->地址管理
> - 购买人信息：会员购中心->购买人信息
""")
    with gr.Column(variant="compact"):
        with gr.Row():
            username_ui = gr.Text(
                value=main_request.get_request_name,  # 修复刷新后显示未登录实际已登录的bug
                label="账号名称",
                interactive=False,
                info="输入配置文件使用的账号名称",
                scale=5,
            )
            gr_file_ui = gr.File(
                label="当前登录信息文件", value=GLOBAL_COOKIE_PATH, scale=1
            )
        with gr.Row():
            upload_ui = gr.UploadButton(label="导入Cookie文件登录", file_types=[".json"])
            add_btn = gr.Button(
                "二维码登录",
            )
            logout_btn = gr.Button("注销当前账号")

            logout_btn.click(fn=logout, inputs=None, outputs=[username_ui, gr_file_ui])

            upload_ui.upload(upload_file, [upload_ui], [username_ui, gr_file_ui])

            add_btn.click(fn=add, inputs=None, outputs=[username_ui, gr_file_ui])

    with gr.Accordion(label="填写你的当前账号所绑定的手机号[可选]", open=False):
        phone_gate_ui = gr.Textbox(
            label="填写你的当前账号所绑定的手机号",
            info="手机号验证出现概率极低，可不填",
            value=main_request.cookieManager.get_config_value("phone", ""),
        )

        def input_phone(_phone):
            main_request.cookieManager.set_config_value("phone", _phone)

        phone_gate_ui.change(fn=input_phone, inputs=phone_gate_ui, outputs=None)

    with gr.Column(variant="compact"):
        info_ui = gr.TextArea(
            info="票务信息", label="配置票的信息", interactive=False, visible=False
        )
        ticket_id_ui = gr.Textbox(
            label="想要抢票的网址",
            interactive=True,
            info="https://show.bilibili.com/platform/detail.html?id=84096或者https://mall.bilibili.com/mall-dayu/neul-next/ticket/detail.html?id=97701",
        )
        ticket_id_btn = gr.Button("获取票信息")
        with gr.Column(visible=False) as inner:
            with gr.Row():
                ticket_info_ui = gr.Dropdown(
                    label="选票",
                    interactive=True,
                    type="index",
                    info="必填，请仔细核对起售时间，千万别选错其他时间点的票",
                )
                data_ui = Calendar(
                    type="string",
                    label="选择日期",
                    info="此票需要你选择的时间,时间是否有效请自行判断",
                    interactive=True,
                )
            with gr.Row():
                people_buyer_ui = gr.Dropdown(
                    label="联系人",
                    interactive=True,
                    type="index",
                    info="必填，如果候选项为空请到「购票人信息」添加",
                )
                address_ui = gr.Dropdown(
                    label="地址",
                    interactive=True,
                    type="index",
                    info="必填，如果候选项为空请到「地址管理」添加",
                )
            people_ui = gr.CheckboxGroup(
                label="身份证实名认证",
                interactive=True,
                type="index",
                info="必填，选几个就代表买几个人的票，在哔哩哔哩客户端-会员购-个人中心-购票人信息中添加",
            )
            config_btn = gr.Button("生成配置")
            config_file_ui = gr.File(visible=False)
            config_output_ui = gr.JSON(
                label="生成配置文件（右上角复制）",
                visible=False,
            )
            config_btn.click(
                fn=on_submit_all,
                inputs=[
                    ticket_id_ui,
                    ticket_info_ui,
                    people_ui,
                    people_buyer_ui,
                    address_ui,
                ],
                outputs=[config_output_ui, config_file_ui],
            )

        ticket_id_btn.click(
            fn=on_submit_ticket_id,
            inputs=ticket_id_ui,
            outputs=[
                ticket_info_ui,
                people_ui,
                people_buyer_ui,
                address_ui,
                inner,
                info_ui,
                data_ui,
            ],
        )

        def on_submit_data(_date):
            global ticket_str_list
            global ticket_value

            try:
                ticket_that_day = main_request.get(
                    url=f"https://show.bilibili.com/api/ticket/project/infoByDate?id={project_id}&date={_date}"
                ).json()["data"]
                ticket_str_list = []
                ticket_value = []
                for screen in ticket_that_day["screen_list"]:
                    screen_name = screen["name"]
                    screen_id = screen["id"]
                    express_fee = screen["express_fee"]
                    for ticket in screen["ticket_list"]:
                        ticket_desc = ticket["desc"]
                        sale_start = ticket["sale_start"]
                        ticket["price"] = ticket_price = ticket["price"] + express_fee
                        ticket["screen"] = screen_name
                        ticket["screen_id"] = screen_id
                        ticket_can_buy = "可购买" if ticket["clickable"] else "不可购买"
                        ticket_str = (
                            f"{screen_name} - {ticket_desc} - ￥{ticket_price / 100}- {ticket_can_buy}"
                            f" - 【起售时间：{sale_start}】"
                        )
                        ticket_str_list.append(ticket_str)
                        ticket_value.append(
                            {"project_id": project_id, "ticket": ticket}
                        )

                return [
                    gr.update(value=_date, visible=True),
                    gr.update(choices=ticket_str_list),
                    gr.update(value=f"当前票日期更新为: {_date}"),
                ]
            except Exception as e:
                return [gr.update(), gr.update(), gr.update(value=e, visible=True)]

        data_ui.change(
            fn=on_submit_data,
            inputs=data_ui,
            outputs=[data_ui, ticket_info_ui, info_ui],
        )
