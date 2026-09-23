"""Strict 1 GiB (1,073,741,824 bytes) PCAP/PCAPNG upload limit validation & chunked pipeline test suite."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from model_service.app import app, JOB_MANAGER
from model_service.jobs import validate_pcap_file, validate_pcap_bytes
from nexsolve_core.config import (
    MAX_PCAP_UPLOAD_BYTES,
    MAX_PCAP_UPLOAD_SIZE,
    MAX_UPLOAD_BYTES,
    PCAP_MAGICS,
    ResourceLimitExceededError,
)

client = TestClient(app)

PCAPNG_MAGIC = bytes.fromhex("0a0d0d0a")
PCAP_MAGIC = bytes.fromhex("d4c3b2a1")


def create_sparse_capture(suffix: str, size: int, magic: bytes = PCAPNG_MAGIC) -> Path:
    """Create an instantaneous sparse file on disk with valid magic bytes and target size."""
    tf = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
    temp_path = Path(tf.name)
    tf.write(magic)
    if size > len(magic):
        tf.truncate(size)
    tf.close()
    return temp_path


class TestStrict1GbUploadLimits:
    def test_01_canonical_constants_byte_definition(self):
        """Verify canonical 1 GiB limit is exactly 1,073,741,824 bytes."""
        assert MAX_PCAP_UPLOAD_BYTES == 1073741824
        assert MAX_PCAP_UPLOAD_BYTES == 1024 * 1024 * 1024
        assert MAX_UPLOAD_BYTES == MAX_PCAP_UPLOAD_BYTES
        assert MAX_PCAP_UPLOAD_SIZE == "1 GiB"

    def test_02_accepts_100_mb_capture(self):
        """100 MB captures (.pcap and .pcapng) are accepted."""
        size_100m = 100 * 1024 * 1024
        for suffix, magic in [(".pcap", PCAP_MAGIC), (".pcapng", PCAPNG_MAGIC)]:
            path = create_sparse_capture(suffix, size_100m, magic)
            try:
                name, clean_suffix, fsize = validate_pcap_file(path)
                assert clean_suffix == suffix
                assert fsize == size_100m
            finally:
                path.unlink(missing_ok=True)

    def test_03_accepts_220_34_mb_capture_bug_fix(self):
        """220.34 MB capture (user-reported bug case) is cleanly accepted."""
        size_220m = int(220.34 * 1024 * 1024)
        assert size_220m < MAX_PCAP_UPLOAD_BYTES

        for suffix, magic in [(".pcapng", PCAPNG_MAGIC), (".pcap", PCAP_MAGIC)]:
            path = create_sparse_capture(suffix, size_220m, magic)
            try:
                name, clean_suffix, fsize = validate_pcap_file(path, f"r&d{suffix}")
                assert clean_suffix == suffix
                assert fsize == size_220m
            finally:
                path.unlink(missing_ok=True)

    def test_04_accepts_500_mb_capture(self):
        """500 MB capture is cleanly accepted."""
        size_500m = 500 * 1024 * 1024
        for suffix, magic in [(".pcap", PCAP_MAGIC), (".pcapng", PCAPNG_MAGIC)]:
            path = create_sparse_capture(suffix, size_500m, magic)
            try:
                name, clean_suffix, fsize = validate_pcap_file(path)
                assert fsize == size_500m
            finally:
                path.unlink(missing_ok=True)

    def test_05_accepts_999_mb_capture(self):
        """999 MB capture is cleanly accepted."""
        size_999m = 999 * 1024 * 1024
        for suffix, magic in [(".pcap", PCAP_MAGIC), (".pcapng", PCAPNG_MAGIC)]:
            path = create_sparse_capture(suffix, size_999m, magic)
            try:
                name, clean_suffix, fsize = validate_pcap_file(path)
                assert fsize == size_999m
            finally:
                path.unlink(missing_ok=True)

    def test_06_accepts_exact_1_gib_boundary(self):
        """Exactly 1 GiB (1,073,741,824 bytes) boundary capture is accepted."""
        size_exact_1gb = 1073741824
        for suffix, magic in [(".pcap", PCAP_MAGIC), (".pcapng", PCAPNG_MAGIC)]:
            path = create_sparse_capture(suffix, size_exact_1gb, magic)
            try:
                name, clean_suffix, fsize = validate_pcap_file(path)
                assert fsize == size_exact_1gb
            finally:
                path.unlink(missing_ok=True)

    def test_07_rejects_1_byte_above_1_gib(self):
        """1 byte above 1 GiB (1,073,741,825 bytes) is rejected with ResourceLimitExceededError."""
        size_over = 1073741825
        for suffix, magic in [(".pcap", PCAP_MAGIC), (".pcapng", PCAPNG_MAGIC)]:
            path = create_sparse_capture(suffix, size_over, magic)
            try:
                with pytest.raises(ResourceLimitExceededError) as exc_info:
                    validate_pcap_file(path)
                err = exc_info.value
                assert err.resource == "upload_bytes"
                assert err.limit == MAX_PCAP_UPLOAD_BYTES
                assert err.observed == size_over
            finally:
                path.unlink(missing_ok=True)

    def test_08_rejects_2_gb_capture(self):
        """2 GB capture (2,147,483,648 bytes) is rejected."""
        size_2gb = 2 * 1024 * 1024 * 1024
        for suffix, magic in [(".pcap", PCAP_MAGIC), (".pcapng", PCAPNG_MAGIC)]:
            path = create_sparse_capture(suffix, size_2gb, magic)
            try:
                with pytest.raises(ResourceLimitExceededError):
                    validate_pcap_file(path)
            finally:
                path.unlink(missing_ok=True)

    def test_09_rejects_5_gb_capture(self):
        """5 GB capture (5,368,709,120 bytes) is rejected."""
        size_5gb = 5 * 1024 * 1024 * 1024
        for suffix, magic in [(".pcap", PCAP_MAGIC), (".pcapng", PCAPNG_MAGIC)]:
            path = create_sparse_capture(suffix, size_5gb, magic)
            try:
                with pytest.raises(ResourceLimitExceededError):
                    validate_pcap_file(path)
            finally:
                path.unlink(missing_ok=True)

    def test_10_rejects_8_23_gb_capture(self):
        """8.23 GB capture (8,836,856,545 bytes) is rejected."""
        size_823gb = int(8.23 * 1024 * 1024 * 1024)
        for suffix, magic in [(".pcap", PCAP_MAGIC), (".pcapng", PCAPNG_MAGIC)]:
            path = create_sparse_capture(suffix, size_823gb, magic)
            try:
                with pytest.raises(ResourceLimitExceededError):
                    validate_pcap_file(path)
            finally:
                path.unlink(missing_ok=True)

    def test_11_rejects_empty_and_corrupt_magic(self):
        """0-byte and corrupted magic bytes are rejected."""
        empty_path = create_sparse_capture(".pcap", 0, b"")
        try:
            with pytest.raises(ValueError, match="empty"):
                validate_pcap_file(empty_path)
        finally:
            empty_path.unlink(missing_ok=True)

        corrupt_path = create_sparse_capture(".pcapng", 1024, b"NOTP")
        try:
            with pytest.raises(RuntimeError, match="supported PCAP/PCAPNG"):
                validate_pcap_file(corrupt_path)
        finally:
            corrupt_path.unlink(missing_ok=True)


class TestChunkedUploadLifecycle:
    def test_chunked_upload_init_chunk_complete_flow(self):
        """Verify the complete chunked upload lifecycle against the API."""
        # 1. Initialize session
        init_res = client.post(
            "/api/pcap/upload/init",
            json={"filename": "test_chunked.pcapng", "total_size": 16, "chunk_size": 8},
        )
        assert init_res.status_code == 201
        data = init_res.json()
        upload_id = data["upload_id"]
        assert data["status"] == "INITIATED"
        assert data["max_size_bytes"] == MAX_PCAP_UPLOAD_BYTES

        # 2. Upload Chunk 0 (first 8 bytes containing valid PCAP-NG magic)
        chunk0 = PCAPNG_MAGIC + b"\x00\x00\x00\x00"
        res_c0 = client.post(
            "/api/pcap/upload/chunk",
            data={"upload_id": upload_id, "chunk_index": 0},
            files={"chunk": ("chunk0.part", chunk0, "application/octet-stream")},
        )
        assert res_c0.status_code == 200
        assert res_c0.json()["chunk_index"] == 0

        # 3. Upload Chunk 1 (second 8 bytes)
        chunk1 = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        res_c1 = client.post(
            "/api/pcap/upload/chunk",
            data={"upload_id": upload_id, "chunk_index": 1},
            files={"chunk": ("chunk1.part", chunk1, "application/octet-stream")},
        )
        assert res_c1.status_code == 200
        assert res_c1.json()["chunk_index"] == 1

        # 4. Complete upload
        res_complete = client.post(
            "/api/pcap/upload/complete",
            json={"upload_id": upload_id},
        )
        assert res_complete.status_code == 202
        job_data = res_complete.json()
        assert "job_id" in job_data
        assert job_data["status"] in ("QUEUED", "PROCESSING")

    def test_chunked_upload_rejects_oversized_init(self):
        """Chunked upload rejects session initialization if declared size > 1 GiB."""
        oversized = MAX_PCAP_UPLOAD_BYTES + 1
        res = client.post(
            "/api/pcap/upload/init",
            json={"filename": "huge.pcap", "total_size": oversized, "chunk_size": 5242880},
        )
        assert res.status_code == 413
        assert "1 GiB" in res.json()["detail"]

    def test_chunked_upload_abort(self):
        """Chunked upload session abort cleans up temporary chunk directory."""
        init_res = client.post(
            "/api/pcap/upload/init",
            json={"filename": "abort_me.pcap", "total_size": 100, "chunk_size": 50},
        )
        upload_id = init_res.json()["upload_id"]
        abort_res = client.post("/api/pcap/upload/abort", json={"upload_id": upload_id})
        assert abort_res.status_code == 200
        assert abort_res.json()["status"] == "ABORTED"

    def test_direct_upload_mime_robustness_and_validation(self):
        """Regression test verifying:
        - valid .pcap upload succeeds
        - valid .pcapng upload succeeds
        - empty or unexpected MIME type does NOT reject a valid PCAP
        - oversized file (>1 GiB) is rejected
        - unsupported extension is rejected
        - target nexsolve_forecast_test_10min.pcap succeeds if present
        """
        # 1. Valid .pcap upload with empty MIME type
        pcap_content = PCAP_MAGIC + b"\x00" * 32
        res_pcap_empty_mime = client.post(
            "/jobs",
            files={"file": ("capture.pcap", pcap_content, "")},
        )
        assert res_pcap_empty_mime.status_code == 202
        assert "job_id" in res_pcap_empty_mime.json()

        # 2. Valid .pcapng upload with application/octet-stream
        pcapng_content = PCAPNG_MAGIC + b"\x00" * 32
        res_pcapng = client.post(
            "/jobs",
            files={"file": ("capture.pcapng", pcapng_content, "application/octet-stream")},
        )
        assert res_pcapng.status_code == 202
        assert "job_id" in res_pcapng.json()

        # 3. Valid .pcap with unusual Windows MIME type
        res_pcap_unusual_mime = client.post(
            "/jobs",
            files={"file": ("test_unusual.pcap", pcap_content, "application/x-unknown-capture")},
        )
        assert res_pcap_unusual_mime.status_code == 202
        assert "job_id" in res_pcap_unusual_mime.json()

        # 4. Unsupported extension rejected with 415
        res_bad_ext = client.post(
            "/jobs",
            files={"file": ("malware.exe", b"MZ\x90\x00", "application/octet-stream")},
        )
        assert res_bad_ext.status_code == 415
        assert "Only .pcap and .pcapng" in res_bad_ext.json()["detail"]

        # 5. Invalid magic rejected with 422
        res_bad_magic = client.post(
            "/jobs",
            files={"file": ("corrupt.pcap", b"NOTAPCAPFILE", "application/vnd.tcpdump.pcap")},
        )
        assert res_bad_magic.status_code == 422
        assert "could not be parsed" in res_bad_magic.json()["detail"]

        # 6. Real local target file test if exists
        target_path = Path(r"C:\Users\saira\OneDrive\Desktop\nexsolve_forecast_test_10min.pcap")
        if target_path.exists():
            with open(target_path, "rb") as f:
                content = f.read()
            res_target = client.post(
                "/jobs",
                files={"file": ("nexsolve_forecast_test_10min.pcap", content, "application/octet-stream")},
            )
            assert res_target.status_code == 202
            assert "job_id" in res_target.json()

