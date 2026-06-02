package conduit

type ServerConfig struct {
    ChannelName    string
    MaxDatafileSize int64
}

func DefaultServerConfig() ServerConfig {
    return ServerConfig{
        ChannelName:    "LUNA_SHARED_MEM",
        MaxDatafileSize: 0x5000000,
    }
}
