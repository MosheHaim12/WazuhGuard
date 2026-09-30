using System.ComponentModel;
using System.Runtime.InteropServices;

namespace WazuhGuard.Vpn;

public sealed record RasConnection(nint Handle, string Name, string DeviceType, string DeviceName,
    Guid CorrelationId, bool AllUsers);
public readonly record struct RasStatus(uint ErrorCode, uint State, uint ConnectionError);
public interface IRasApi
{
    IReadOnlyList<RasConnection> Enumerate();
    RasStatus GetStatus(nint handle);
    uint HangUp(nint handle);
}

public sealed class NativeRasApi : IRasApi
{
    public const uint Success = 0, InvalidHandle = 6, BufferTooSmall = 603, Connected = 0x2000;
    public IReadOnlyList<RasConnection> Enumerate()
    {
        var size = Marshal.SizeOf<RasConn>();
        uint bytes = (uint)size;
        // The connection count can change between sizing and retrieval. Retry a bounded number of times.
        for (var attempt = 0; attempt < 5; attempt++)
        {
            if (bytes > 16 * 1024 * 1024 || bytes < size) throw new InvalidDataException("Invalid RAS buffer size.");
            var allocated = bytes;
            var buffer = Marshal.AllocHGlobal(checked((int)allocated));
            try
            {
                Marshal.WriteInt32(buffer, size);
                var result = RasEnumConnectionsW(buffer, ref bytes, out var count);
                if (result == BufferTooSmall) continue;
                if (result != Success) throw new Win32Exception((int)result, $"RasEnumConnectionsW failed ({result}).");
                if ((ulong)count * (uint)size > allocated) throw new InvalidDataException("RAS returned an invalid connection count.");
                var connections = new List<RasConnection>(checked((int)count));
                for (var i = 0; i < count; i++)
                {
                    var item = Marshal.PtrToStructure<RasConn>(buffer + checked(i * size));
                    connections.Add(new(item.Handle, item.EntryName, item.DeviceType, item.DeviceName,
                        item.CorrelationId, (item.Flags & 1) != 0));
                }
                return connections;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        throw new InvalidOperationException("RAS connection list changed too often; retry next monitoring cycle.");
    }

    public RasStatus GetStatus(nint handle)
    {
        var status = new RasConnStatus { Size = (uint)Marshal.SizeOf<RasConnStatus>() };
        var error = RasGetConnectStatusW(handle, ref status);
        return new(error, status.State, status.Error);
    }
    public uint HangUp(nint handle) => RasHangUpW(handle);

    // ras.h, Unicode, default Windows packing. DWORD/LUID fields are 32-bit even on x64.
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct RasConn
    {
        public uint Size;
        public nint Handle;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 257)] public string EntryName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 17)] public string DeviceType;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 129)] public string DeviceName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string Phonebook;
        public uint SubEntry;
        public Guid EntryId;
        public uint Flags;
        public uint LuidLow;
        public int LuidHigh;
        public Guid CorrelationId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct RasConnStatus
    {
        public uint Size, State, Error;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 17)] public string DeviceType;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 129)] public string DeviceName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 129)] public string PhoneNumber;
        public RasTunnelEndpoint Local, Remote;
        public uint SubState;
    }

    [StructLayout(LayoutKind.Explicit, Size = 20)]
    public struct RasTunnelEndpoint
    {
        [FieldOffset(0)] public uint Type;
        // Union of IN_ADDR (4 bytes) and IN6_ADDR (16 bytes).
        [FieldOffset(4)] public uint Address0;
        [FieldOffset(8)] public uint Address1;
        [FieldOffset(12)] public uint Address2;
        [FieldOffset(16)] public uint Address3;
    }

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("rasapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint RasEnumConnectionsW(nint buffer, ref uint bytes, out uint count);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("rasapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint RasGetConnectStatusW(nint handle, ref RasConnStatus status);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("rasapi32.dll", ExactSpelling = true)]
    private static extern uint RasHangUpW(nint handle);
}
