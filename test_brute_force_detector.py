import pytest

from brute_force_detector import BruteForceDetector


def test_parse_logs():
    detector = BruteForceDetector()
    log_data = "[2026-03-19 01:23:45] 192.168.0.1 failed login"
    expected_result = [{'timestamp': '2026-03-19 01:23:45', 'ip': '192.168.0.1', 'result': 'failed'}]
    assert detector.parse_logs(log_data) == expected_result


def test_analyze_log_success():
    detector = BruteForceDetector()
    log_data = "[2026-03-19 01:23:46] 192.168.0.1 successful login"
    detector.analyze_log(log_data)
    assert detector.failed_attempts['192.168.0.1'] == 0


def test_analyze_log_failed():
    detector = BruteForceDetector()
    log_data = "[2026-03-19 01:23:47] 192.168.0.1 failed login"
    detector.analyze_log(log_data)
    assert detector.failed_attempts['192.168.0.1'] == 1


def test_record_failed_attempt():
    detector = BruteForceDetector()
    ip = "192.168.0.1"
    detector.record_failed_attempt(ip)
    assert detector.failed_attempts[ip] == 1


def test_block_ip():
    detector = BruteForceDetector()
    ip = "192.168.0.1"
    detector.block_ip(ip)
    assert ip in detector.blocked_ips


def test_unblock_ip():
    detector = BruteForceDetector()
    ip = "192.168.0.1"
    detector.block_ip(ip)
    detector.unblock_ip(ip)
    assert ip not in detector.blocked_ips


def test_edge_case_empty_logs():
    detector = BruteForceDetector()
    log_data = ""
    result = detector.parse_logs(log_data)
    assert result == []


def test_edge_case_invalid_log_format():
    detector = BruteForceDetector()
    log_data = "Invalid log format"
    result = detector.parse_logs(log_data)
    assert result == []  # Assuming it gracefully handles invalid formats


if __name__ == '__main__':
    pytest.main()