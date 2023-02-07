#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

void usage() {
	printf("syntax : signal-strength <interface> <mac>\n");
	printf("sample : signal-strength mon0 00:11:22:33:44:55\n");
}






typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 3) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}


struct ieee80211_radiotap_header {
	u_int8_t        it_version;
	u_int8_t        it_pad;
	u_int16_t       it_len;

	u_int64_t       it_present;
	

	u_int8_t        flag;
	u_int8_t		data_rate;
	u_int16_t       channel_frequency;
	u_int16_t       channel_flag;
	u_int8_t		signal_strength;
	// u_int8_t		dummy;
	// u_int16_t 		rx_flags;
	// u_int8_t		signal_strength_2;

};

struct beacon_frame{
    u_int8_t    subtype;
    u_int8_t    flags;

    u_int16_t   duration;

    u_int8_t DA[6];
    u_int8_t SA[6];
    u_int8_t BSS_ID[6];
    
    u_int16_t   fragment_sequence_number;

} __attribute__((__packed__));





char* get_month(int month_int){
	if (month_int == 1){
		return "Jan";
	}
	else if(month_int == 2){
		return "Feb";
	}
	else if(month_int == 3){
		return "Mar";
	}
	else if(month_int == 4){
		return "Apr";
	}
	else if(month_int == 5){
		return "May";
	}
	else if(month_int == 6){
		return "Jun";
	}
	else if(month_int == 7){
		return "Jul";
	}
	else if(month_int == 8){
		return "Aug";
	}
	else if(month_int == 9){
		return "Sep";
	}
	else if(month_int == 10){
		return "Oct";
	}
	else if(month_int == 11){
		return "Nov";
	}
	else if(month_int == 12){
		return "Dec";
	}
}	


int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1, errbuf);

	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	struct pcap_pkthdr* header;
	const u_char* packet;
	
	struct ieee80211_radiotap_header* radiotap_header;
	struct beacon_frame* beacon;

	

	

	while(true){
		int res = pcap_next_ex(pcap, &header, &packet);
  		
		time_t t = time(NULL);
		struct tm tm = *localtime(&t);

		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			return 0;
		}
		


		radiotap_header = packet;
		beacon = packet + radiotap_header->it_len;

		u_int8_t SA[6];
		char* source_mac_ptr = strtok(argv[2], ":");
		
		for(int i=0; source_mac_ptr != NULL ;i++){
			SA[i] = (u_int8_t)strtol(source_mac_ptr, NULL, 16);
			source_mac_ptr = strtok(NULL, ":");
		}
		// for(int i = 0; i< 6; i++)
		// 	printf("%02x ",SA[i]);

		// for(int i = 0; i< 6; i++)
		// 	printf("%02x ",beacon->SA[i]);
		// printf("    ");
		// for(int i = 0; i< 6; i++)
		// 	printf("%02x ",SA[i]);
		// printf("\n");

		char* month;
		if(!memcmp(SA, beacon -> SA, 6) && (beacon->subtype == 0x80)){
			// for(int i = 0; i< 6; i++)
			// 	printf("%02x ",beacon->SA[i]);

			// printf("%d", radiotap_header->flag);
			// printf("-%d", ~(radiotap_header->signal_strength)+1);
			
			// printf("%d\n", (~(radiotap_header->signal_strength))+1);
			
			
  			tm = *localtime(&t);
			month = get_month(tm.tm_mon+1);
			printf("%s    %d,  %d  %02d:%02d:%02d KST          -%d\n", month, tm.tm_mday, tm.tm_year+1900, tm.tm_hour, tm.tm_min, tm.tm_sec, ((radiotap_header->signal_strength)^255)+1);

			// printf("-%d \n", ~radiotap_header->signal_strength+1);
			// printf("%d\n  ", ~radiotap_header->signal_strength);
			
			
			// for(int i = 0; i< 6; i++)
			// 	printf("%d\n",radiotap_header->signal_strength);
			// return 0;
		}
		// printf("\n");
		

		// printf("%d\n", radiotap_header ->signal_strength);
	}
	
	return 0;
}	