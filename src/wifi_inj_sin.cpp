#include "wifi_inj_sin.h"
#include "nvs_flash.h"
#include "esp_mac.h"
#include "esp_wifi.h"
#include "esp_heap_caps.h"
#include "esp_log.h"

static const char *TAG = "wifi injection and sniffer";

void WiFi_injection_sniffer::init(){ //setup_wifi
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
    // ESP_ERROR_CHECK(esp_wifi_config_80211_tx(WIFI_IF_AP, &tx_rate_config));

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
	wifi_config_t ap_config = {
		.ap = {
			.ssid = "",
			.ssid_len = 0,
			.channel = 1,
			.authmode = WIFI_AUTH_OPEN,
			.ssid_hidden = 1,
			.max_connection = 1,
			.beacon_interval = 60000
		}
	};
	ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_config));

    // ESP_ERROR_CHECK(esp_wifi_set_bandwidth(WIFI_IF_AP, WIFI_BW_HT40));
    ESP_ERROR_CHECK(esp_wifi_config_80211_tx_rate(WIFI_IF_AP, WIFI_PHY_RATE_54M));
    // wifi_bandwidths_t bw;
    // ESP_ERROR_CHECK(esp_wifi_get_bandwidths(WIFI_IF_AP, &bw));
    // ESP_LOGI(TAG, "Wi-Fi AP bandwidths: 2.4GHz: %d, 5GHz: %d", bw.ghz_2g, bw.ghz_5g);

    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
    ESP_ERROR_CHECK(esp_wifi_set_channel(13, WIFI_SECOND_CHAN_NONE));

    /* Sinffer */
    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_DATA
    };
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_ctrl_filter(&filter));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb((wifi_promiscuous_cb_t)&packet_received_cb));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));

    //set mac address
    // ESP_ERROR_CHECK(esp_wifi_get_mac(WIFI_IF_AP, _mac)); // cause error esp_wifi_80211_tx en_sys_seq
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
};

void WiFi_injection_sniffer::set_wifi_fixed_rate(uint8_t value){
    ESP_ERROR_CHECK(esp_wifi_stop());
    ESP_ERROR_CHECK(esp_wifi_config_80211_tx_rate(WIFI_IF_AP, (wifi_phy_rate_t)value));
    ESP_ERROR_CHECK(esp_wifi_start());
}

IRAM_ATTR void WiFi_injection_sniffer::send_air2ground_video_packet(bool last, uint8_t* packet_data, size_t packet_size, uint32_t frame_index, uint8_t part_index){
    Air2Ground_Video_Packet& packet = *(Air2Ground_Video_Packet*)(packet_data+WLAN_PAYLOAD_OFFSET);
        packet.type = Air2Ground_Header::Type::Video;
        packet.frame_index = frame_index; /*NEED TO CHANGE*/
        packet.part_index = part_index;
        packet.last_part = last ? 1 : 0;
        packet.size = packet_size; /*NEED TO REMOVE*/
        packet.pong = 0;

    _injection(packet_data, packet_size+sizeof(Air2Ground_Video_Packet)); //TODO: return error
};

/* Private */
IRAM_ATTR void WiFi_injection_sniffer::packet_received_cb(uint8_t* buf, uint8_t type){
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *payload = pkt->payload;

    //mac compare, sender check
    WiFi_injection_sniffer instance;
    const uint8_t *src_mac = &payload[10];
    for (int i = 0; i < 6; i++) {
        if (src_mac[i] != instance.target_src_mac[i]){
            ESP_LOGD(TAG, "No Matched Source MAC");
            return;
        }
    }

    //memcpy following part
    ESP_LOGD(TAG, "PACK TYPE: %d", type);

    int8_t rssi = pkt->rx_ctrl.rssi;
    ESP_LOGD(TAG, "RSSI: %d dBm", rssi);

    int8_t noise_floor = pkt->rx_ctrl.noise_floor;
    ESP_LOGD(TAG, "Noise_floor: %d dBm", rssi);

    ESP_LOGD(TAG, "sig_mode: %u", pkt->rx_ctrl.sig_mode);           // 0: 11bg, 1: HT (11n), 3: VHT (11ac)
    ESP_LOGD(TAG, "mcs: %u", pkt->rx_ctrl.mcs);                     // Modulation Coding Scheme (0–76)
    ESP_LOGD(TAG, "cwb: %u", pkt->rx_ctrl.cwb);                     // Channel bandwidth: 0 = 20MHz, 1 = 40MHz
    ESP_LOGD(TAG, "smoothing: %u", pkt->rx_ctrl.smoothing);         // Channel estimate smoothing recommendation
    ESP_LOGD(TAG, "not_sounding: %u", pkt->rx_ctrl.not_sounding);   // PPDU sounding indication
    ESP_LOGD(TAG, "aggregation: %u", pkt->rx_ctrl.aggregation);     // 0 = MPDU, 1 = AMPDU
    ESP_LOGD(TAG, "stbc: %u", pkt->rx_ctrl.stbc);                   // Space Time Block Coding (0 = none, 1 = used)
    ESP_LOGD(TAG, "fec_coding: %u", pkt->rx_ctrl.fec_coding);       // LDPC FEC coding flag (for 11n)
    ESP_LOGD(TAG, "sgi: %u", pkt->rx_ctrl.sgi);                     // Short Guard Interval flag

    Air2Ground_Header* air2ground_payload = (Air2Ground_Header*)payload;
    if(air2ground_payload->type == Air2Ground_Header::Type::Video){

    } else if(air2ground_payload->type == Air2Ground_Header::Type::Telemetry){

    }else{
        ESP_LOGE(TAG,"Unknow type");
    };
};

IRAM_ATTR void WiFi_injection_sniffer::_injection(uint8_t* data, size_t len){
    if(data == nullptr || len == 0 || len > WLAN_MAX_PAYLOAD_SIZE){
        ESP_LOGE(TAG, "Invalid data or length for injection: %d", len);
        return; //invalid data
    }
    memcpy(data, WLAN_IEEE_HEADER_AIR2GROUND, WLAN_IEEE_HEADER_SIZE);
    memcpy(data + 10, _mac, 6);

    esp_err_t err;
    do{
        err = esp_wifi_80211_tx(WIFI_IF_AP, data, WLAN_IEEE_HEADER_SIZE + len, false);
        if (err == ESP_ERR_NO_MEM) {
        ESP_LOGE(TAG, "WiFi Tx rate is too low");
        vTaskDelay(portTICK_PERIOD_MS*5);
        }
    }while(err == ESP_ERR_NO_MEM);
    
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to send data: %s", esp_err_to_name(err));
    }
};

//Rx logic
// 1. rx call back, check sender, memcpy to ring buffer
// 2. tick to get the data and its info for fec
// 3. memcpy to frame buffer
// 4. uvc call back to get the frame