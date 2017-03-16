from .device_state import DeviceStateChannel
from .http_blob import HttpBlobDataChannel
from .report import ReportDataChannel

channels = dict(
    http_blob=HttpBlobDataChannel,
    report_standard=ReportDataChannel,
    report_state=DeviceStateChannel
)

__all__ = ['channels']