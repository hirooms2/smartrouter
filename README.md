# SMART ROUTER

유동인구 빅데이터 축적을 위한 와이파이 모니터링 기기 제작

# 모식도

![Alt text](/structure.png)

모바일폰은 주변 AP를 찾기 위해 probe request frame을 주기적으로 발송하게 됩니다. 이를 AP 혹은 저희가 자체 제작한 기기의 monitor 모드를 통해 신호를 캡쳐하여 해당 프레임에 담긴 mac address, time, RSSI등을 서버로 전송합니다. 서버에서는 이를 DB와 연동하여 처리를 한 후 최종적으로 Web과 App 등에 가공된 정보를 제공합니다. 

![Alt text](/structure2.png)

하나의 AP가 cover할 수 있는 영역 안에 몇 개의 디바이스가 있는지 고유 Number로 분류하고 이와 같은 식을 전국적으로 확대하여 시간에 따른 구축 포인트 별 인구밀도를 구하게 됩니다.

