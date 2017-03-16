import struct
import sys
import os
import time
import win32file
import win32service

from epclib.win32._internal.servicemanager import scm

SERVICENAME = "ramdump"
DRIVERPATH = "FIXME"


def CTL_CODE(device_type, function, method, access):
    return (device_type << 16) | (access << 14) | (function << 2) | method

# IOCTLS for interacting with the driver.
CTRL_IOCTRL = CTL_CODE(0x22, 0x101, 0, 3)
INFO_IOCTRL = CTL_CODE(0x22, 0x103, 0, 3)


class Image(object):
    """This class abstracts the image."""
    buffer_size = 1024 * 1024

    def __init__(self, fd):
        self.flags = {}
        self.fd = fd
        self.SetMode()
        self.ParseMemoryRuns()
        self.GetInfo()

    FIELDS = (["CR3", "NtBuildNumber", "KernBase", "KDBG"] +
              ["KPCR%02d" % i for i in range(32)] +
              ["PfnDataBase", "PsLoadedModuleList", "PsActiveProcessHead"] +
              ["Padding%s" % i for i in range(0xff)] +
              ["NumberOfRuns"])

    def ParseMemoryRuns(self):
        self.runs = []

        result = win32file.DeviceIoControl(
            self.fd, INFO_IOCTRL, "", 102400, None)

        fmt_string = "Q" * len(self.FIELDS)
        self.memory_parameters = dict(zip(self.FIELDS, struct.unpack_from(
                    fmt_string, result)))

        self.dtb = self.memory_parameters["CR3"]
        self.kdbg = self.memory_parameters["KDBG"]

        offset = struct.calcsize(fmt_string)

        for x in range(self.memory_parameters["NumberOfRuns"]):
            start, length = struct.unpack_from("QQ", result, x * 16 + offset)
            self.runs.append((start, length))

    def GetInfo(self):
        for k, v in sorted(self.memory_parameters.items()):
            if k.startswith("Pad"):
                continue

            if not v:
                continue

            print("%s: \t%#08x (%s)" % (k, v, v))

        print("Memory ranges:")
        print("Start\t\tEnd\t\tLength")

        for start, length in self.runs:
            print("0x%X\t\t0x%X\t\t0x%X" % (start, start+length, length))

    def SetMode(self):
        if self.flags["mode"] == "iospace":
            mode = 0
        elif self.flags["mode"] == "physical":
            mode = 1
        elif self.flags["mode"] == "pte":
            mode = 2
        elif self.flags["mode"] == "pte_pci":
            mode = 3
        else:
            raise RuntimeError("Mode %s not supported" % self.flags["mode"])

        win32file.DeviceIoControl(
            self.fd, CTRL_IOCTRL, struct.pack("I", mode), 0, None)

    def PadWithNulls(self, outfd, length):
        while length > 0:
            to_write = min(length, self.buffer_size)
            outfd.write("\x00" * to_write)
            length -= to_write

    def DumpWithRead(self, output_filename):
        """Read the image and write all the data to a raw file."""
        with open(output_filename, "wb") as outfd:
            offset = 0
            for start, length in self.runs:
                if start > offset:
                    print("\nPadding from 0x%X to 0x%X\n" % (offset, start))
                    self.PadWithNulls(outfd, start - offset)

                offset = start
                end = start + length
                while offset < end:
                    to_read = min(self.buffer_size, end - offset)
                    win32file.SetFilePointer(self.fd, offset, 0)

                    _, data = win32file.ReadFile(self.fd, to_read)
                    outfd.write(data)

                    offset += to_read

                    offset_in_mb = offset/1024/1024
                    if not offset_in_mb % 50:
                        sys.stdout.write("\n%04dMB\t" % offset_in_mb)

                    sys.stdout.write(".")
                    sys.stdout.flush()


class Memory(object):
    def dump_ram(self, outfile):
        self.hsvc = self.__load_driver(SERVICENAME, DRIVERPATH)
        if not self.hsvc:
            return False
        self.__dump_ram(outfile)
        self.__unload_driver()

    def __unload_driver(self):
            scm.delete_service(self.servicename)

    def __load_driver(self, servicename, driverpath):
        """Load the driver and image the memory."""
        # Check the driver is somewhere
        if not driverpath or not os.access(driverpath, os.R_OK):
            print("You must specify a valid driver file.")
            return False
        self.servicename = servicename

        # Must have absolute path here.
        driver = os.path.join(os.getcwd(), driverpath)

        return scm.load_driver(self.servicename, driver)

    def __dump_ram(self, outfile):
        try:
            fd = win32file.CreateFile(
                "\\\\.\\" + self.servicename,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
                None,
                win32file.OPEN_EXISTING,
                win32file.FILE_ATTRIBUTE_NORMAL,
                None)

            try:
                t = time.time()
                image = Image(fd)
                print("Imaging to %s" % outfile)
                image.DumpWithRead(outfile)
                print("\nCompleted in %s seconds" % (time.time() - t))
            finally:
                win32file.CloseHandle(fd)
        finally:
            try:
                scm.stop_service(SERVICENAME)
            except win32service.error:
                pass