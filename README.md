# TCP/IP 에코 서버 암호화,복호화
----------------------------------------------------  
#### 참고 사이트 : https://idea-sketch.tistory.com/3  
해당 참고 사이트의 코드를 조금 바꾸어 사용하였다.  
암호화,복호화 알고리즘은 동일하니 해당 사이트를 참고하는 것을 추천한다.  
  
![image](https://user-images.githubusercontent.com/63215359/114308334-7047a600-9b1e-11eb-8fff-093b14f4bb0b.png)  
  
![image](https://user-images.githubusercontent.com/63215359/114308551-55c1fc80-9b1f-11eb-9b0b-3b99df22c358.png)  
  
매번 서버<->클라 패킷을 보낼 때마다 난수의 공개키를 같이 보내어 조금이라도 해커들을 귀찮게 만들고 싶었다.  
보안성에 이득이 될련지는 모르겠지만..  
  
![image](https://user-images.githubusercontent.com/63215359/114308775-e8629b80-9b1f-11eb-80d7-9e0c9c7c4651.png)  
  
암호화,복호화 알고리즘 함수이다.  
간단한 바이트 연산을 통해 데이터를 꼬아놓고 다시 역산하여 본래 데이터를 복구하는 방식이다.  
과정에서 키값이 3개가 사용이 되는데 하나는 위에서 난수로 보내는 공개키이고 나머지 두 키는 서버와 클라이언트가 고유적으로 가지고 있는 키이다.  
비공개 키라고 하기에는 해당 코드에서는 서버,클라가 같은 키를 가지고 있어야 하기 때문에 보안적으로는 강력하다고 말할 순 없다.  
어디까지나 역시 해커들을 조금이라도 더 귀찮게 하기 위한 수단일 뿐..  
  
매개 변수는 순서대로 공캐 키값, 원본, 암호 혹은 복호화 된 데이터, 암호 혹은 복호화 시작 위치, 원본 사이즈 이다.  
시작 위치가 필요한 이유는 패킷 설계 시 보통 순서대로 사이즈,프로토콜,데이터 이렇게 설계하게 되는데 사이즈와 프로토콜 사이에 공개키를 추가하여 설계했다.  
최종적으로 사이즈 - 공개키 - 프로토콜 - 데이터 이런식으로 설계가 될 것이다. ( 단, 해당 에코 서버에선 프로토콜은 넣지 않았다. )  
이 때에 최소한 복호화를 위해서는 공개키에 대한 정보를 알고 있어야 하기 때문에 공개키는 암호화 하지 않고 보낸다.  
그렇기에 암호화 시작 위치를 임의로 정하여 사이즈와 공개키는 암호화 하지 않도록 하는 것을 목적으로 하였다.  
만일 사이즈와 공개키를 따로 암호화,복호화 하여 사용하고자 한다면 시작 위치는 0 으로 지정해도 상관 없다.  
( 사실 그 방법이 훨씬 보안적으로 좋기 때문에 필자도 곧 시도해 볼 생각이다.. )  
  
![image](https://user-images.githubusercontent.com/63215359/114309083-e9e09380-9b20-11eb-9496-e41802e92100.png)  
  
![image](https://user-images.githubusercontent.com/63215359/114309097-fd8bfa00-9b20-11eb-9396-2cb8fcfd8f4e.png)  
  
패킹,언패킹 함수이고 우선 패킹 부분은 직관적으로 보이듯이 버퍼에 데이터를 순서대로 쌓은 후에 임시 버퍼를 준비했다.  
원본 버퍼를 암호화 하여 임시 버퍼에 저장한 후, 다시 원본 버퍼에 복제하는 것으로 암호화는 완료된다.  
복호화는 암호화 되어 있지 않은 공개키를 먼저 받은 후에 해당 공개키로 수신 받은 버퍼의 데이터를 복호화 시킨다.  
복호화 된 데이터를 받은 임시 버퍼를 다시 기존 버퍼에 복제하여 나머지 데이터를 차례차례 풀어내면 완료된다.  
과정은 엄청 단순하고 간단하지만 그만큼 허점이 많다..  
( ex. 상대가 나와 다른 키로 암호화하여 데이터를 보내면 당연히 잘못된 메모리에 접근 하다가 터져서 서버가 죽어버린다던가.. )  
  
이런 부분이 대한 예외처리나 최적화, 보안성 강화와 같은 숙제가 많이 남았지만 그래도 생각했던 것처럼 작동한 것에 보람을 느낀 작업이었다.  
