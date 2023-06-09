
from prettytable import PrettyTable
import bdkpython as bdk
import p2p 



def output_addresses_values(transaction, network):
    #print(f'Getting output addresses for txid {transaction.txid}')
    columns = []
    for output in transaction.output():
        try:
            add = '' if output.value == 0 else bdk.Address.from_script(output.script_pubkey, network).as_string()
            value = output.value
        except:
            add = ''
            value = 'unknown'
        columns.append((add, value))
    return columns


def transaction_from_string(s):
    return bdk.Transaction(bytes.fromhex(s))

def transaction_from_bytes(transaction_bytes):
    return bdk.Transaction(transaction_bytes)


def transaction_table(transaction):
    x = PrettyTable()
    input_column = [f'{inp.previous_output.txid}:{inp.previous_output.vout}' for inp in  transaction.input()]
    output_addresses, output_values = zip(*output_addresses_values(transaction, bdk.Network.BITCOIN))

    max_rows= max([len(x) for x in [input_column, output_addresses, output_values]])

    def stretch_column(c, max_rows):
        return list(c) + ['' for i in range(max_rows-len(c))]

    x.title = f'Transaction: {transaction.txid()}'
    x.add_column("Inputs", stretch_column(input_column, max_rows))
    x.add_column("Output Address", stretch_column(output_addresses, max_rows))
    x.add_column("Amount", stretch_column(output_values, max_rows))

    return x



def pretty_tx_from_bytes(tx_bytes):
    return print(transaction_table(transaction_from_bytes(tx_bytes)))


if __name__ == '__main__':
    p2p.listen(p2p.get_bitcoin_peer(), call_back_tx=pretty_tx_from_bytes)