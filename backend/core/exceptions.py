"""
==========================================================
CyberScan Enterprise
Core Exceptions Module
----------------------------------------------------------
Author  : Graduation Project Team
Purpose : Custom exceptions used across the scanning engine.
Version : 1.0
==========================================================
"""


class CyberScanException(Exception):
    """
    Base exception for all CyberScan errors.
    """
    pass


# ==========================================================
# Network Exceptions
# ==========================================================

class NetworkException(CyberScanException):
    """General network error."""
    pass


class ConnectionException(NetworkException):
    """Connection could not be established."""
    pass


class TimeoutException(NetworkException):
    """The request exceeded the configured timeout."""
    pass


class RedirectException(NetworkException):
    """Too many redirects occurred."""
    pass


class SSLException(NetworkException):
    """SSL/TLS validation failed."""
    pass


class ProxyException(NetworkException):
    """Proxy connection failed."""
    pass


# ==========================================================
# HTTP Exceptions
# ==========================================================

class HTTPException(CyberScanException):
    """General HTTP exception."""
    pass


class InvalidURLException(HTTPException):
    """Invalid URL supplied."""
    pass


class InvalidResponseException(HTTPException):
    """Invalid HTTP response."""
    pass


class ResponseTooLargeException(HTTPException):
    """Response exceeded allowed size."""
    pass


# ==========================================================
# Scanner Exceptions
# ==========================================================

class ScannerException(CyberScanException):
    """General scanner exception."""
    pass


class ScannerNotSupportedException(ScannerException):
    """Scanner not implemented."""
    pass


class ScanCancelledException(ScannerException):
    """Scan cancelled."""
    pass


class DetectionException(ScannerException):
    """Detection logic failed."""
    pass


# ==========================================================
# Report Exceptions
# ==========================================================

class ReportException(CyberScanException):
    """Report generation failed."""
    pass


# ==========================================================
# Database Exceptions
# ==========================================================

class DatabaseException(CyberScanException):
    """Database operation failed."""
    pass


# ==========================================================
# AI Exceptions
# ==========================================================

class AIException(CyberScanException):
    """AI analysis failed."""
    pass