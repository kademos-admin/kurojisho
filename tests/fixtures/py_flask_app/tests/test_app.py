from shop.app import get_order


def test_get_order():
    assert get_order(1) is not None
