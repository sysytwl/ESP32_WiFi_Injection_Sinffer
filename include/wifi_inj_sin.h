#pragma once
#include <cstring>
#ifdef ESP_PLATFORM
  #include "esp_log.h"
  #include "esp_err.h"
  #ifdef CONFIG_SPIRAM
    #include "esp_heap_caps.h"
  #endif
#else
  #define ESP_LOGE(tag, format, ...) fprintf(stderr, format, ##__VA_ARGS__)
  #define ESP_LOGI(tag, format, ...) fprintf(stdout, format, ##__VA_ARGS__)
#endif


//#include "esp_private/wifi.h"
//esp_err_t esp_wifi_internal_reg_rxcb(wifi_interface_t ifx, wifi_rxcb_t fn);
//esp_err_t esp_wifi_set_tx_done_cb(wifi_tx_done_cb_t cb);
//esp_wifi_set_promiscuous_rx_cb(packet_received_cb)
//#include "crc.h"

#define DEFAULT_WIFI_CHANNEL 13
#define PACKET_VERSION 2

//https://www.geeksforgeeks.org/ieee-802-11-mac-frame/
//https://en.wikipedia.org/wiki/802.11_Frame_Types
//each byte shifted from lower bits
//08 = 00 version, 01 frame type, 0000 subtype
constexpr uint8_t WLAN_IEEE_HEADER_AIR2GROUND[]={
  0x08, 0x00,//frame control
  0x00, 0x00,//2-3: Duration
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,// 4-9: Destination address (broadcast)
  0x94, 0xb5, 0x55, 0x26, 0xe2, 0xfc,// 10-15: Source address/from
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,// 16-21: BSSID/to
  0x10, 0x86// 22-23: Sequence / fragment number
};

constexpr uint8_t WLAN_IEEE_HEADER_GROUND2AIR[]={
  0x08, 0x01, 
  0x00, 0x00,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
  0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
  0x10, 0x86
};

constexpr size_t WLAN_IEEE_HEADER_SIZE = sizeof(WLAN_IEEE_HEADER_AIR2GROUND);
static_assert(WLAN_IEEE_HEADER_SIZE == 24, "");
constexpr size_t WLAN_MAX_PACKET_SIZE = 1024;
constexpr size_t WLAN_MAX_PAYLOAD_SIZE = WLAN_MAX_PACKET_SIZE - WLAN_IEEE_HEADER_SIZE;
constexpr size_t WLAN_PAYLOAD_OFFSET = WLAN_IEEE_HEADER_SIZE;



struct Ground2Air_Header{
    enum Type: uint8_t{
        Telemetry,
        Config,
    } type;
    uint8_t packet_version = PACKET_VERSION; //version of the packet structure
};

struct Ground2Air_Data_Packet : Ground2Air_Header{
    uint16_t channel_data [4];
    uint8_t channel_data_1 [10];
};
static_assert(sizeof(Ground2Air_Data_Packet) < WLAN_MAX_PAYLOAD_SIZE, "");

struct Ground2Air_Config_Packet: Ground2Air_Header{
    uint8_t ping = 0; //used for latency measurement
    uint8_t wifi_rate;
    uint8_t wifi_channel;
    uint8_t fec_codec_k;
    uint8_t fec_codec_n;

    //Description of some settings: https://heyrick.eu/blog/index.php?diary=20210418&keitai=0
    struct Camera_config{
        uint8_t resolution;
        uint8_t quality = 0;//0 - 63  0-auto
        int8_t brightness = 0;//-2 - 2
        int8_t contrast = 0;//-2 - 2
        int8_t saturation = 1;//-2 - 2
        int8_t sharpness = 0;//-2 - 3
        uint8_t denoise = 0;  //0..8, ov5640 only
        uint8_t special_effect = 0;//0 - 6
        bool awb = true;
        bool awb_gain = true;
        uint8_t wb_mode = 0;//0 - 4
        bool aec = true; //automatic exposure control
        bool aec2 = true; //enable aec DSP (better processing?)
        int8_t ae_level = 1;//-2 - 2, for aec=true
        uint16_t aec_value = 204;//0 - 1200 ISO, for aec=false
        bool agc = true;  //automatic gain control
        uint8_t agc_gain = 0;//30 - 6, for agc=false
        uint8_t gainceiling = 0;//0 - 6, for agc=true. 0=2x, 1=4x, 2=8x,3=16x,4=32x,5=64x,6=128x
        bool bpc = true;
        bool wpc = true;
        bool raw_gma = true;
        bool lenc = true;
        bool hmirror = false;
        bool vflip = false;
        bool dcw = true;
        bool ov5640NightMode = false;
    } camera;
};



struct Air2Ground_Header{
    enum Type: uint8_t{
        Video,
        Telemetry,
    } type;
    uint8_t part_index;
    uint8_t frame_index;
    uint8_t pong = 0; //used for latency measurement
    uint8_t packet_version = PACKET_VERSION;
};

struct Air2Ground_Video_Packet : Air2Ground_Header{
    uint8_t frame;
    //data follows
    //uint8_t data[AIR2GROUND_VIDEO_MAX_PAYLOAD_SIZE];
};
constexpr size_t Air2Ground_Video_Packet_Header_Size = sizeof(Air2Ground_Video_Packet);
static_assert(Air2Ground_Video_Packet_Header_Size == 16, "");
constexpr size_t AIR2GROUND_VIDEO_HEADER_OFFSET = WLAN_PAYLOAD_OFFSET + sizeof(Air2Ground_Video_Packet);
constexpr size_t AIR2GROUND_VIDEO_MAX_PAYLOAD_SIZE = WLAN_MAX_PAYLOAD_SIZE - sizeof(Air2Ground_Video_Packet);

struct Air2Ground_status_Packet : Air2Ground_Header{
    union {
        uint32_t raw;
        struct {
            uint32_t reserved           : 4;  // padding to total 32 bits
            uint32_t SDDetected         : 1;
            uint32_t SDSlow             : 1;
            uint32_t SDError            : 1;
            uint32_t air_record_state   : 1;
            uint32_t SDFreeSpaceGB16    : 12;
            uint32_t SDTotalSpaceGB16   : 12;
        } sdcard;
    };

    uint32_t curr_quality : 6;
    uint8_t isOV5640 : 1;

    uint8_t rssi;
    uint8_t noiseFloorDbm;

    uint8_t captureFPS;
    uint8_t cam_ovf_count;
};

struct Air2Ground_MAVLink_Packet : Air2Ground_Header{

};



class WiFi_injection_sniffer{
public:
    void init(uint16_t *channel_data, int8_t *noise_floor, int8_t *rssi);
    
    void set_wifi_fixed_rate(uint8_t value);

    //process settings not related to camera sensor setup
    static void handle_ground2air_config_packetEx1(Ground2Air_Config_Packet& src){
  
    }

    static void handle_ground2air_config_packet(Ground2Air_Config_Packet& src){

    }

    void send_air2ground_osd_packet(uint8_t* packet_data){
        // Air2Ground_OSD_Packet& packet = *(Air2Ground_OSD_Packet*)packet_data;
        // packet.type = Air2Ground_Header::Type::OSD;
        // packet.size = sizeof(Air2Ground_OSD_Packet);
        // packet.pong = 0;//s_ground2air_config_packet.ping;
        // packet.version = PACKET_VERSION;
        // packet.crc = 0;
    };

    esp_err_t send_air2ground_video_packet(bool last, uint8_t* packet_data, size_t packet_size, uint32_t frame_index, uint8_t part_index);

    float calculate_throughput();

private:
    static void packet_received_cb(uint8_t* buf, uint8_t type);
    esp_err_t _injection(uint8_t* data, size_t len);
    uint8_t _mac[6];

    uint8_t *_tx_header;

    //throughput
    int64_t _last_time = 0;
    size_t _send_size = 0;

    //ground2air
    static uint16_t *_channel_data;
    static int8_t *_noise_floor;
    static int8_t *_rssi;
};


