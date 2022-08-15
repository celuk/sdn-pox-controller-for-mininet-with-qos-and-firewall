# sdn-pox-controller-for-mininet-with-qos-and-firewall
SDN Controller with QoS and Firewall implemented for Mininet

ELE 466 Proje

Seyyid Hikmet Çelik

181201047

GitHub pox python3 İçin Düzeltilmiş Link: https://github.com/celuk/pox-python3

İki python kodu var.

bil452_controller.py --> SDN POX + QoS + Firewall Kontrolcü Kodu

bil452_topo.py       --> Mininet custom topoloji dosyası

bil452_controller.py 'yi pox/forwarding dosya yoluna atıp terminalde

./pox.py forwarding.bil452_controller

ya da QoS için

./pox.py forwarding.bil452_controller -q

ile çalıştırabilirsiniz.

Diğer bir terminalde ise mininet işlemlerini yapın.

Mininet kalıntılarını temizleyin.

sudo mn -c

Custom topoloji ve uzak kontrolcü ile minneti başlatın, kendi topolojimiz üzerinde kendi kontrolcümüz başlayacak.

sudo mn --controller remote --custom ./bil452_topo.py --topo bil452_topo

Bir hosttan diğerine pingleri aşağıdaki gibi atabilirsiniz.

h7 ping -c 1 h4
h1 ping -c 1 h3
h1 ping -c 1 h6
h2 ping -c 1 h4

Tüm hostlardan birbirlerine topluca ping atabilirsiniz.

pingall

