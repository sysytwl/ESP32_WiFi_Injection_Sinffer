#include "wifi_inj_sin.h"
#include "nvs_flash.h"
#include "esp_mac.h"
#include "esp_wifi.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_timer.h"

uint16_t* WiFi_injection_sniffer::_channel_data = nullptr;
int8_t* WiFi_injection_sniffer::_noise_floor = nullptr;
int8_t* WiFi_injection_sniffer::_rssi = nullptr;

static const char *TAG = "wifi injection and sniffer";

void WiFi_injection_sniffer::init(uint16_t *channel_data, int8_t *noise_floor, int8_t *rssi){ //setup_wifi
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    // wifi_tx_rate_config_t tx_rate_config = {
    //     .phymode = WIFI_PHY_MODE_HT40,
    //     .rate = WIFI_PHY_RATE_MCS7_SGI, // Set the desired transmission rate
    //     .ersu = false,
    //     .dcm = false,
    // };
    // ESP_ERROR_CHECK(esp_wifi_config_80211_tx(WIFI_MODE, &tx_rate_config));

    wifi_country_t county_config={
        .cc="JP",
        .schan=1,
        .nchan=14,
        .max_tx_power=84,
        .policy=WIFI_COUNTRY_POLICY_MANUAL,
    };
    ESP_ERROR_CHECK(esp_wifi_set_country(&county_config));

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
	wifi_config_t ap_config = {
		.ap = {
			.ssid = "",
			.ssid_len = 0,
			.channel = 13,
			.authmode = WIFI_AUTH_OPEN,
			.ssid_hidden = 1,
			.max_connection = 1,
			.beacon_interval = 60000
		}
	};
	ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_config));

    // ESP_ERROR_CHECK(esp_wifi_set_bandwidth(WIFI_MODE, WIFI_BW_HT40));
    ESP_ERROR_CHECK(esp_wifi_config_80211_tx_rate(WIFI_IF_AP, WIFI_PHY_RATE_24M));
    // wifi_bandwidths_t bw;
    // ESP_ERROR_CHECK(esp_wifi_get_bandwidths(WIFI_MODE, &bw));
    // ESP_LOGI(TAG, "Wi-Fi AP bandwidths: 2.4GHz: %d, 5GHz: %d", bw.ghz_2g, bw.ghz_5g);

    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
    ESP_ERROR_CHECK(esp_wifi_set_channel(DEFAULT_WIFI_CHANNEL, WIFI_SECOND_CHAN_NONE));

    /* Sinffer */
    _channel_data = channel_data;
    _noise_floor = noise_floor;
    _rssi = rssi;

    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_DATA
    };
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_ctrl_filter(&filter));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb((wifi_promiscuous_cb_t)&packet_received_cb));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));

    //set mac address
    // ESP_ERROR_CHECK(esp_wifi_get_mac(WIFI_MODE, _mac)); // cause error esp_wifi_80211_tx en_sys_seq
    // ESP_LOGI(TAG, "Wi-Fi AP MAC: %02x:%02x:%02x:%02x:%02x:%02x", _mac[0], _mac[1], _mac[2], _mac[3], _mac[4], _mac[5]);

    // ESP_ERROR_CHECK(esp_read_mac(_mac,ESP_MAC_WIFI_STA)); // might cause error 
    // ESP_LOGI(TAG, "Wi-Fi STA MAC: %02x:%02x:%02x:%02x:%02x:%02x", _mac[0], _mac[1], _mac[2], _mac[3], _mac[4], _mac[5]);

    // ESP_ERROR_CHECK(esp_read_mac(_mac,ESP_MAC_BT));
    // ESP_LOGI(TAG, "BT MAC: %02x:%02x:%02x:%02x:%02x:%02x", _mac[0], _mac[1], _mac[2], _mac[3], _mac[4], _mac[5]);

    ESP_ERROR_CHECK(esp_read_mac(_mac,ESP_MAC_ETH));
    ESP_LOGI(TAG, "ETH MAC: %02x:%02x:%02x:%02x:%02x:%02x", _mac[0], _mac[1], _mac[2], _mac[3], _mac[4], _mac[5]);

    // ESP_ERROR_CHECK(esp_read_mac(_mac,ESP_MAC_BASE)); // Base MAC is the same as Wi-Fi STA MAC
    // ESP_LOGI(TAG, "BASE MAC: %02x:%02x:%02x:%02x:%02x:%02x", _mac[0], _mac[1], _mac[2], _mac[3], _mac[4], _mac[5]);

    // ESP_ERROR_CHECK(esp_efuse_mac_get_default(_mac)); // same as base mac
    // ESP_LOGI(TAG, "ESP32 efuse MAC: %02x:%02x:%02x:%02x:%02x:%02x", _mac[0], _mac[1], _mac[2], _mac[3], _mac[4], _mac[5]);

    _tx_header = new uint8_t [WLAN_IEEE_HEADER_SIZE];
    memcpy(_tx_header, WLAN_IEEE_HEADER_AIR2GROUND, WLAN_IEEE_HEADER_SIZE);
    memcpy(_tx_header + 10, _mac, 6);
};

void WiFi_injection_sniffer::set_wifi_fixed_rate(uint8_t value){
    ESP_ERROR_CHECK(esp_wifi_stop());
    ESP_ERROR_CHECK(esp_wifi_config_80211_tx_rate(WIFI_IF_AP, (wifi_phy_rate_t)value));
    ESP_ERROR_CHECK(esp_wifi_start());
}

IRAM_ATTR esp_err_t WiFi_injection_sniffer::send_air2ground_video_packet(uint8_t* packet_data, size_t packet_size, uint32_t frame_index, uint8_t part_index){
    Air2Ground_Header& packet = *(Air2Ground_Header*)(packet_data+WLAN_IEEE_HEADER_SIZE);
        packet.type = Air2Ground_Header::Type::Video;
        packet.frame_index = frame_index;
        packet.part_index = part_index;
        packet.packet_version = PACKET_VERSION;

    return _injection(packet_data, packet_size+sizeof(Air2Ground_Header));
};

/* Private */
IRAM_ATTR void WiFi_injection_sniffer::packet_received_cb(uint8_t* buf, uint8_t type){
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *payload = pkt->payload;

    //mac compare, sender check
    WiFi_injection_sniffer instance;
    const uint8_t *src_mac = payload + 16;
    if (memcmp(src_mac, &instance._mac, 6) != 0) return; //not the pack for us

    *_rssi = pkt->rx_ctrl.rssi;
    *_noise_floor = pkt->rx_ctrl.noise_floor;

    Ground2Air_Header* ground2air_payload = (Ground2Air_Header*)payload;
    if(ground2air_payload->type == Ground2Air_Header::Type::Telemetry){
        //Ground2Air_Data_Packet *ground2air_payload = (Ground2Air_Data_Packet*)payload;
        //memcpy(_channel_data, &ground2air_payload->channel_data[0], sizeof(ground2air_payload->channel_data));
        //for (uint8_t i=0; i<10; i++){
        //    _channel_data[i+4] = ground2air_payload->channel_data_1[i];
        //}
    }else if(ground2air_payload->type == Ground2Air_Header::Type::Config){

    }else{
        ESP_LOGE(TAG,"Unknow type");
    };
};

IRAM_ATTR esp_err_t WiFi_injection_sniffer::_injection(uint8_t* data, size_t len){
    // if(data == nullptr || len == 0 || len > WLAN_MAX_PAYLOAD_SIZE){
    //     ESP_LOGE(TAG, "Invalid data or length for injection: %d", len);
    //     return ESP_ERR_INVALID_SIZE; //invalid data
    // }    
    memcpy(data, _tx_header, WLAN_IEEE_HEADER_SIZE);

    size_t size_to_send = WLAN_IEEE_HEADER_SIZE + len;
    _send_size += size_to_send;
    return esp_wifi_80211_tx(WIFI_IF_AP, data, size_to_send, false);
};

float WiFi_injection_sniffer::calculate_throughput(){
    int64_t current_time = esp_timer_get_time();
    int64_t duration_time = current_time - _last_time;
    float result = (float)_send_size / (float)duration_time * 1000.0;
    _last_time = esp_timer_get_time();
    _send_size = 0;

    return result;
}

//Rx logic
// 1. rx call back, check sender, memcpy to ring buffer
// 2. tick to get the data and its info for fec
// 3. memcpy to frame buffer
// 4. uvc call back to get the frame