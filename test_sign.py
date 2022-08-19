import hashlib
import time
from typing import Dict
from uuid import uuid4

import requests


def create_api_sign(payload: Dict[str, str], ts: int, nonce: str, ver: str) -> str:
    payload = dict(
        ts=str(ts),
        n=nonce,
        v=ver,
        **payload,
    )
    raw = '&'.join('{}={}'.format(k, payload[k]) for k in sorted(payload.keys()))
    sign = hashlib.sha1(raw.encode()).hexdigest()
    return sign


def test():
    payload = {'name': 'abc', 'age': 10}
    ts = int(time.time())
    nonce = uuid4().hex
    ver = 'v1'
    sign = create_api_sign(payload, ts, nonce, ver)
    print(sign, ts, nonce, ver)

    headers = {
        'x-api-ts': str(ts),
        'x-api-nonce': nonce,
        'x-api-ver': ver,
        'x-api-sign': sign,
        'X-True-Client-Ip': '112.64.63.67',
    }
    r = requests.get('http://localhost:18000', params=payload, headers=headers)
    print(r.status_code, r.json())


def main():
    test()


if __name__ == '__main__':
    main()
