# -*- coding: utf-8 -*-
# @Date     : 2025/2/25 13:54
# @Author   : q275343119
# @File     : ips.py
# @Description:


def get_ips_from_file(filename):
    """
    file context:
    "0.0.0.0/8","-","-"
    "1.0.0.0/24","AU","Australia"
    "1.0.1.0/24","CN","China"
    "1.0.2.0/23","CN","China"
    "1.0.4.0/22","AU","Australia"
    Args:
        filename:

    Returns:

    """
    with open(filename, "r", encoding="utf-8") as f:
        lines = f.readline()
        while lines:
            if lines.split(",")[1].replace('"', "") != "-":
                yield lines.split(",")[0].replace('"', "")
            lines = f.readline()


if __name__ == '__main__':
    ip_file = "IP2LOCATION-LITE-DB1.NEW.CSV"
    for ip in get_ips_from_file(ip_file):
        print(ip)
        break