import pytest

from src.port_scanner.cli import parse_ports


def test_parse_ports_default():
    ports = parse_ports(None)
    assert len(ports) > 0


def test_parse_ports_list():
    ports = parse_ports("22,80,443,80")
    assert ports == [22, 80, 443]


def test_parse_ports_range():
    ports = parse_ports("1-5")
    assert ports == [1, 2, 3, 4, 5]


def test_parse_ports_invalid_range():
    with pytest.raises(ValueError):
        parse_ports("100-1")
