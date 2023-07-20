# Listen to the bitcoin p2p transaction data

`bitcoin-p2p` can listen (no verification) to the p2p traffic of a bitcoin node and display the transactions like:

```python
import socket, asyncio
import bdkpython as bdk
from bitcoin_p2p import tools, p2p
# see https://github.com/andreasgriffin/bitcoin-p2p

global_dict = {}

def callback_min_feerate(feerate):
    global_dict['feerate'] = feerate
    

def callback_recv_tx(tx_bytes):
    transaction = tools.transaction_from_bytes(tx_bytes)
    print(tools.transaction_table(transaction))
    
    

await p2p.listen(p2p.get_bitcoin_peer(), callback_recv_tx=callback_recv_tx, callback_min_feerate=callback_min_feerate )
```
with the output:
```
Received sendheaders command
Received sendcmpct
Received sendcmpct
Received ping
Received getheaders
Received feefilter, minimum feerate is 4477
Inventory count 18
+---------------------------------------------------------------------------------------------------------------------+
|                    Transaction: b3b7bcec03759c53580be4722227239f83197ce966af73139f6348f4d19b2e7d                    |
+--------------------------------------------------------------------+------------------------------------+-----------+
|                               Inputs                               |           Output Address           |   Amount  |
+--------------------------------------------------------------------+------------------------------------+-----------+
| d90af911da1d24b03b01047a9f57af5df354cff1f6394ea01200b8577712766d:0 | 33mX6JQUgXTun9m6DkmXMBugxHboYrUdbp | 105511580 |
+--------------------------------------------------------------------+------------------------------------+-----------+
+----------------------------------------------------------------------------------------------------------------------------------------------+
|                                Transaction: c4b75ce9c4c3fcf43054d7fbe502585a4be30b80dac31f8bfa4845aeab06a967                                 |
+--------------------------------------------------------------------+----------------------------------------------------------------+--------+
|                               Inputs                               |                         Output Address                         | Amount |
+--------------------------------------------------------------------+----------------------------------------------------------------+--------+
| c13f038c2b30b057c73d8dc694d2a6b742538e8b31e387478e30c715e6e97993:1 |               16G1xYBbiNG78LSuZdMqp6tux5xvVp9Wxh               |  546   |
| 0ae8edcd1299f7672e02e4c02c02d00a78367731913d1cc7a66118a3b1b7be55:1 | bc1parapxed82turc2hj99wgdxf0hz96s240200dnw0zx30f8t9vmgaql98ha0 | 94681  |
+--------------------------------------------------------------------+----------------------------------------------------------------+--------+
+----------------------------------------------------------------------------------------------------------------------+
|                    Transaction: 05455dcec23f81c2273eb003390b4427d1e3660709c45c6b90347525fc2ad5bc                     |
+--------------------------------------------------------------------+------------------------------------+------------+
|                               Inputs                               |           Output Address           |   Amount   |
+--------------------------------------------------------------------+------------------------------------+------------+
| d768d96b5aba03582a9e0c71a6859cc629cfb7dce40e53012b797f50ae45d063:1 | 3614Z6uv6tc738p76XP6uYVkkPcueVFCcY |  40000000  |
|                                                                    | 12vVbKJbTYYYvDZw3B8V6HRsjhesQCc121 | 1049819426 |
+--------------------------------------------------------------------+------------------------------------+------------+
```





# Install package



### From pypi

```shell
pip install bitcoin_p2p
```



###  From git

```shell
python setup.py sdist bdist_wheel
pip install dist/bitcoin_p2p-0.1-py3-none-any.whl   
```



