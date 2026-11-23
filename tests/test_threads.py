"""Concurrency tests, mainly for free-threaded builds (3.14t, 3.15t), where chafernet runs without the GIL."""

import threading

from chafernet import Chafernet, Keyset

THREADS = 8
ROUNDS = 200


def test_shared_chafernet_across_threads():
    chaf = Chafernet(Keyset.generate().with_new_key())
    errors: list[BaseException] = []
    barrier = threading.Barrier(THREADS)

    def work(n: int) -> None:
        try:
            barrier.wait()
            for i in range(ROUNDS):
                plaintext = f"thread {n} round {i}".encode() * 50
                aad = bytes([n])
                token = chaf.encrypt(plaintext, aad=aad)
                assert chaf.decrypt(token, 60, aad=aad) == plaintext
        except BaseException as error:  # noqa: BLE001
            errors.append(error)

    threads = [threading.Thread(target=work, args=(n,)) for n in range(THREADS)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
