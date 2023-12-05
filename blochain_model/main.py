import hashlib
import datetime

from Crypto.Random import random  # для случайного выбора майнера
from STREEBOG import streebog_str, streebog_bytes
from GOST3410 import get_keys, get_dgst, sign_data, verify_signature
# todo: заменить буржуйскую крипту на госты

# параметры системы
INITIAL_COINBASE_AMOUNT = 1000000
MINING_DIFFICULTY = 10
BLOCK_REWARD = 5
PRIME_BIT_SIZE = 1024

# значения для читаемого вывода
TAB2 = '\t' * 2
TAB3 = '\t' * 3
TAB4 = '\t' * 4
TAB5 = '\t' * 5
TAB6 = '\t' * 6
LEFT_P = '{'
RIGHT_P = '}'


def calculate_merkle_root(data_list: list):
    """Вычисление корня древа Меркла"""
    leaf_hashes = [leaf.calculate_hash() for leaf in data_list]

    while len(leaf_hashes) > 1:
        new_leaf_hashes = []

        for i in range(0, len(leaf_hashes), 2):
            if i + 1 >= len(leaf_hashes):
                leaf_hashes.append(leaf_hashes[i])

            combined_hash = hashlib.sha256((leaf_hashes[i] + leaf_hashes[i + 1]).encode()).hexdigest()
            new_leaf_hashes.append(combined_hash)

        leaf_hashes = new_leaf_hashes

    return leaf_hashes[0]


def verify_transaction_signature(tx):
    message = ""
    for transaction_input in tx.inputs:
        message += str(transaction_input['input_address']) + str(transaction_input['input_amount'])
    for transaction_output in tx.outputs:
        message += str(transaction_output['output_address']) + str(transaction_output['output_amount'])

    _hash = streebog_str(message)

    if tx.signature == 0 or tx.public_key == 0:
        return True

    if verify_signature(signature=tx.signature, pub=tx.public_key, dgst=get_dgst(_hash.encode())):
        return True
    return False


class Transaction:
    def __init__(self, inputs: list[dict[str, int]], outputs: list[dict[str, int]], signature: hex, public_key):
        """Инициализация транзакции"""
        self.inputs = inputs
        self.outputs = outputs
        self.signature = signature
        self.public_key = public_key

    def calculate_hash(self):
        """Вычисление хеш-кода блока"""
        transaction_str = f"{self.inputs}{self.outputs}{self.signature}{self.public_key}"
        return hashlib.sha256(transaction_str.encode()).hexdigest()

    def __repr__(self):
        """Вывод транзакции в читаемом виде"""
        res = [f'\n{TAB4}{LEFT_P}\n{TAB5}Входы транзакции:']
        for i, inp in enumerate(self.inputs, 1):
            res.append(f'{TAB6}Вход {i}\n{TAB6}{str(inp)}')

        res.append(f'{TAB5}Выходы транзакции:')
        for i, out in enumerate(self.outputs, 1):
            res.append(f'{TAB6}Выход {i}\n{TAB6}{str(out)}')

        res.append(f'{TAB5}Подпись: {self.signature}')
        res.append(f'{TAB5}Открытый ключ: {self.public_key}')
        res.append(f'{TAB4}{RIGHT_P}\n')
        return '\n'.join(res)


class Block:
    def __init__(self, height: int, prev_hash: hex, coinbase: int, transactions: list[Transaction]):
        """Инициализация блока"""
        self.height = height
        self.time = datetime.datetime.now()
        self.merkle_root = 0x0
        self.prev_hash = prev_hash
        self.nonce = 0
        self.hash = None

        self.coinbase = coinbase
        self.transactions = transactions

    def mine(self):
        """Добыча блока"""
        target = 2 ** (256 - MINING_DIFFICULTY)
        self.hash = self.calculate_hash()
        while int(self.hash, 16) >= target:
            self.nonce += 1
            self.hash = self.calculate_hash()

    def calculate_hash(self):
        """Вычисление хеш-кода блока"""
        block_str = f"{self.height}{self.time}{self.prev_hash}{self.coinbase}{self.nonce}"
        return hashlib.sha256(block_str.encode()).hexdigest()

    def __repr__(self):
        """Вывод блока в читаемом виде"""
        res = [f'\n\t{LEFT_P}\n{TAB2}Заголовок блока:',
               f'{TAB3}Номер блока: {self.height}',
               f'{TAB3}Дата и время создания: {self.time}',
               f'{TAB3}Корень древа Меркла: {self.merkle_root}',
               f'{TAB3}Хеш-код предыдущего блока: {self.prev_hash}',
               f'{TAB3}Nonce: {self.nonce}',
               f'{TAB3}Хеш-код текущего блока: {self.hash}',
               F'{TAB2}Тело блока:',
               f'{TAB3}Coinbase: {self.coinbase}',
               f'{TAB3}Транзакции:']

        for i, tx in enumerate(self.transactions, 1):
            res.append(f'{TAB4}Транзакция {i}{tx}')
        res.append(f'\t{RIGHT_P}\n')

        return '\n'.join(res)


class Client:
    def __init__(self, name: str):
        """Инициализация клиента"""
        self.name = name
        self.pk, self.sk = get_keys()
        self.address = streebog_str(str(self.pk))
        self.utxo = []
        self.balance = 0
        self.checked_blocks = set()

    def create_transaction(self, inputs: list[dict[str, int]], outputs: list[dict[str, int]]):
        """Создание транзакции"""
        transaction = Transaction(inputs, outputs, None, self.pk)

        message = ""
        for transaction_input in inputs:
            message += str(transaction_input['input_address']) + str(transaction_input['input_amount'])
        for transaction_output in outputs:
            message += str(transaction_output['output_address']) + str(transaction_output['output_amount'])

        h = streebog_str(message)
        signature = sign_data(data_for_signing=h.encode(), prv=self.sk)
        transaction.signature = signature
        return transaction

    def read_transaction(self, block: Block):
        """Чтение транзакции"""
        if block.height in self.checked_blocks:
            return

        for transaction in block.transactions:
            for transaction_input in transaction.inputs:
                utxo = {'address': transaction_input['input_address'], 'amount': transaction_input['input_amount']}
                if utxo["address"] == self.address:
                    self.utxo.remove(utxo)
                    self.balance -= utxo["amount"]

            for transaction_output in transaction.outputs:
                utxo = {'address': transaction_output['output_address'], 'amount': transaction_output['output_amount']}
                if utxo["address"] == self.address:
                    self.utxo.append(utxo)
                    self.balance += utxo["amount"]

        self.checked_blocks.add(block.height)

    def get_balance(self):
        """Получение текущего баланса пользователя"""
        return self.balance


class Node:
    def __init__(self, node_id: int, client: Client):
        """Инициализация узла сети"""
        self.node_id = node_id
        self.chain = []
        self.utxo = [{'address': 0x0, 'amount': INITIAL_COINBASE_AMOUNT}]  # список UTXO
        self.miner = client
        self.current_transactions = []

    def create_genesis_block(self):
        """Создание генезис-блока"""
        miner_transaction = self.create_miner_transaction()
        genesis_block = Block(0, 0x0, INITIAL_COINBASE_AMOUNT, [miner_transaction])
        genesis_block.mine()
        self.finalize_block(genesis_block)
        self.chain.append(genesis_block)
        return genesis_block

    def mine_block(self):
        """Добыча блока"""
        miner_transaction = self.create_miner_transaction()
        self.current_transactions.insert(0, miner_transaction)

        new_block = Block(len(self.chain),
                          self.chain[-1].hash,
                          self.chain[-1].coinbase - BLOCK_REWARD,
                          self.current_transactions)
        new_block.merkle_root = calculate_merkle_root(new_block.transactions)
        new_block.mine()

        # финализация блока
        self.finalize_block(new_block)
        self.chain.append(new_block)
        # рассылка нового блока остальным нодам
        self.current_transactions = []
        return new_block

    def create_miner_transaction(self):
        """Создание транзакции, в которой выплачивается вознаграждение майнеру"""
        miner_inputs = [
            {
                'input_address': 0x0,
                'input_amount': self.chain[-1].coinbase - BLOCK_REWARD if len(
                    self.chain) > 0 else INITIAL_COINBASE_AMOUNT
            }
        ]
        miner_outputs = [
            {
                'output_address': self.miner.address,
                'output_amount': BLOCK_REWARD
            },
            {
                'output_address': 0x0,
                'output_amount': self.chain[-1].coinbase - 2 * BLOCK_REWARD if len(
                    self.chain) > 0 else INITIAL_COINBASE_AMOUNT - BLOCK_REWARD
            }
        ]
        return Transaction(inputs=miner_inputs, outputs=miner_outputs, signature=0x0, public_key=0x0)

    def add_transactions(self, transactions):
        """Добавление транзакций в мемпул"""
        self.current_transactions.extend(transactions)

    def finalize_block(self, block):
        """Обновление utxo"""
        # исключение input_UTXO каждой транзакции из своего списка UTXO
        utxo_backup = self.utxo[:]
        for transaction in block.transactions:
            for transaction_input in transaction.inputs:
                utxo = {'address': transaction_input['input_address'],
                        'amount': transaction_input['input_amount']}
                if utxo in self.utxo:
                    self.utxo.remove(utxo)
                else:
                    print(f'Нода {self.node_id}: Ошибка. Повторная трата монет')
                    self.utxo = utxo_backup
                    return False

        # добавление output_UTXO каждой транзакции в свой список UTXO
        for transaction in block.transactions:
            for transaction_output in transaction.outputs:
                utxo = {'address': transaction_output['output_address'],
                        'amount': transaction_output['output_amount']}
                self.utxo.append(utxo)

    def receive_block(self, block):
        """Получение блока от другого узла сети"""
        if len(self.chain) == 0:
            self.finalize_block(block)
            self.chain.append(block)
            return
        is_block_valid = self.validate_block(block)
        if is_block_valid:
            print(f'Нода {self.node_id}: Все проверки прошли успешно')
        else:
            print(f'Нода {self.node_id}: Не все проверки прошли успешно')

    def validate_block(self, block):
        """Проверка валидности блока"""
        # 1) Пересчет дерева Меркла и сравнение корневого хэш-кода
        merkle_root = calculate_merkle_root(block.transactions)
        if merkle_root != block.merkle_root:
            print(f'Нода {self.node_id}: Корневой хэш-код не совпал')
            return False

        # 2) Проверка правильности решения майнером
        target = 2 ** (256 - MINING_DIFFICULTY)
        if int(block.hash, 16) >= target:
            print(f'Нода {self.node_id}: Проверка правильности решение майнером провалилась')
            return False

        # 3) Проверка номера блока
        if block.height != len(self.chain):
            print(f'Нода {self.node_id}: Проверка номера блока провалилась')
            return False

        # 4) Проверка хэш-кода предыдущего блока
        if block.height > 0 and block.prev_hash != self.chain[-1].hash:
            print(block.prev_hash, self.chain[-1].hash)
            print(f'Нода {self.node_id}: Проверка хэш-кода предыдущего блока провалилась')
            return False

        # 5) Проверка времени создания блока
        if block.height > 0 and block.time <= self.chain[-1].time:
            print(f'Нода {self.node_id}: Проверка времени создания блока')
            return False

        # 6) Проверка значения coinbase
        if block.coinbase <= 0 or block.coinbase != self.chain[-1].coinbase - BLOCK_REWARD:
            print(f'Нода {self.node_id}: Проверка значения coinbase провалилась')
            return False

        # 7) Проверка UTXO транзакций
        for transaction in block.transactions:
            for transaction_input in transaction.inputs:
                utxo = {'address': transaction_input['input_address'], 'amount': transaction_input['input_amount']}
                if utxo not in self.utxo:
                    print(utxo, self.utxo)
                    print(f'Нода {self.node_id}: Проверка UTXO транзакций провалилась')
                    return False

        # 8) Проверка суммы входов и выходов транзакций
        for transaction in block.transactions:
            input_sum = sum(transaction_input['input_amount'] for transaction_input in transaction.inputs)
            output_sum = sum(transaction_output['output_amount'] for transaction_output in transaction.outputs)
            if input_sum < output_sum:
                print(f'Нода {self.node_id}: Проверка суммы входов и выходов транзакций провалилась')
                return False

        # 9) Проверка цифровых подписей
        for transaction in block.transactions:
           if not verify_transaction_signature(transaction):
               print('Проверка цифровых подписей провалилась')
               return False
        # todo: check transactions signatures

        # utxo обновляются здесь
        # print(self.utxo)
        if not self.finalize_block(block):
            return False
        # print(self.utxo)

        # все проверки пройдены успешно, включаем блок в цепочку
        self.chain.append(block)
        return True


def update_balances(clients, block):
    for client in clients:
        client.read_transaction(block)
        print(client.get_balance())


def setup():
    client1 = Client('Alice')
    client2 = Client('Dima')
    client3 = Client('Vlad')
    client4 = Client('Anton')
    clients = [client1, client2, client3, client4]
    node1 = Node(1, client1)
    node2 = Node(2, client2)
    node3 = Node(3, client3)
    nodes = [node1, node2, node3]
    return clients, nodes


def get_genesis_block(clients, nodes):
    miner_node = random.randint(0, 2)
    print(nodes[miner_node].utxo)
    current_block = nodes[miner_node].create_genesis_block()
    for i in range(3):
        if i != miner_node:
            nodes[i].receive_block(current_block)
    update_balances(clients, nodes[miner_node - 1].chain[-1])
    return miner_node


def get_next_block(clients, nodes, txs, broken_block=False):
    miner_node = random.randint(0, 2)
    nodes[miner_node].add_transactions(txs)
    current_block = nodes[miner_node].mine_block()
    if broken_block:
        current_block.hash = current_block.hash[::-1]
    for i in range(3):
        if i != miner_node:
            nodes[i].receive_block(current_block)
    print(nodes[miner_node].utxo)
    print(nodes[miner_node - 1].utxo)
    update_balances(clients, nodes[miner_node - 1].chain[-1])


def normal():
    # кайфовый сценарий
    # создание клиентов и нод
    clients, nodes = setup()

    miner_node = get_genesis_block(clients, nodes)

    client_inputs = [
        {
            'input_address': clients[miner_node].address,
            'input_amount': 5
        }
    ]
    client_outputs = [
        {
            'output_address': clients[miner_node].address,
            'output_amount': 2
        },
        {
            'output_address': clients[3].address,
            'output_amount': 3
        }
    ]
    tx = clients[miner_node].create_transaction(client_inputs, client_outputs)
    get_next_block(clients, nodes, [tx])
    # 2 block

    client_inputs = [
        {
            'input_address': clients[3].address,
            'input_amount': 3
        }
    ]
    client_outputs = [
        {
            'output_address': clients[3].address,
            'output_amount': 1
        },
        {
            'output_address': clients[1].address,
            'output_amount': 2
        }
    ]
    tx = clients[3].create_transaction(client_inputs, client_outputs)
    get_next_block(clients, nodes, [tx])


def bad1():
    # плохой сценарий
    clients, nodes = setup()
    # genesis block
    miner_node = get_genesis_block(clients, nodes)

    # 1 block
    client_inputs = [
        {
            'input_address': clients[miner_node].address,
            'input_amount': 5
        }
    ]
    client_outputs = [
        {
            'output_address': clients[miner_node].address,
            'output_amount': 2
        },
        {
            'output_address': clients[3].address,
            'output_amount': 3
        }
    ]
    tx = clients[miner_node].create_transaction(client_inputs, client_outputs)
    get_next_block(clients, nodes, [tx, tx])


def bad2():
    clients, nodes = setup()
    get_genesis_block(clients, nodes)
    get_next_block(clients, nodes, [], True)


def bad3():
    clients, nodes = setup()
    miner_node = get_genesis_block(clients, nodes)
    client_inputs = [
        {
            'input_address': clients[miner_node].address,
            'input_amount': 5
        }
    ]
    client_outputs = [
        {
            'output_address': clients[miner_node].address,
            'output_amount': 3
        },
        {
            'output_address': clients[3].address,
            'output_amount': 3
        }
    ]
    tx = clients[miner_node].create_transaction(client_inputs, client_outputs)
    get_next_block(clients, nodes, [tx])


# Пример использования
if __name__ == '__main__':
    normal()
    # bad1()
    # bad2()
    # bad3()
