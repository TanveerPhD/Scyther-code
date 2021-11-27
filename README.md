usertype TimeStamp ;
usertype SessionKey;
usertype nonce;
hashfunction H;
secret XOR: Function ;

secret  IDU, PWU,BKU,KGW, SA,SPSD,SPU,SIDSD,CP,RA,RB,RC,SIDO,TC,A22;

macro KLO=H(PWU,IDU,BKU);
macro CTLO={PSD,SPU,SIDO}KLO;
macro TAG=H(SPSD,SPU,SIDO);

macro CTG={SPSD,SPSD,SIDSD}SA;
macro TAGG=H(SPSD,SPSD,SIDSD);



protocol REAP-IIoT(U,GW, SD)
{
    role U
    {
secret A22;
var CT4, TAG4;
macro KLO1=XOR(PWRU,IDRU,KRU);
macro CTLO1={PSD,SPU,SIDO}KLO1;
macro TAG1=H(SPSD,SPU,SIDO);
match(TAG,TAG1);
macro TAG2=H(RA,SIDSD);
macro CT1={RA,SIDSD}SPU;

send_1(U,GW,CT1, TAG2);
recv_3(SD, U,CT4,TAG4);

macro A22=H(SPU,SIDO,RA);

macro A3={CT4}A22;
macro TAG44=H(A3);
match(TAG44,TAG4);

macro SK=H(A22,A3,TC);





claim(U,Secret, SK);



claim(U,Alive);
claim(U,Niagree);
claim(U,Nisynch);    
    }

    role GW
    {

macro CTG1={SPSD,SPSD,SIDSD}SA;
macro TAGG1=H(SPSD,SPSD,SIDSD);
match(TAGG,TAGG1);
recv_1(U,GW,CT1, TAG2);
macro CT11={CT1}SPU;
#macro  W=XOR(CP,UP);
macro TAG22=H(RA,SIDSD);
match(TAG22,TAG2);

macro A=H(SPU,SIDO,RA);
macro CT3={RB,A}SPSD;
macro TAG3=H(RB,A);
send_2(GW,SD, CT3,TAG3);


claim(GW,Alive);
claim(GW,Weakagree);
claim(GW,Niagree);
claim(GW,Nisynch);    
   }

    role SD
    {
recv_2(GW,SD, CT3,TAG3);


macro CT32={RB,A}SPSD;
macro A2=H(SPU,SIDO,RA);
macro TAG33=H(RB,A);
match(TAG33,TAG3);
macro A3=XOR(RB,RC,SIDSD,SPSD);
macro SK=H(A2,A3,TC);
macro TAG4=H(A3);

macro CT4={A3}A2;
send_3(SD, U,CT4,TAG4);

claim(SD,Secret, SK);

claim(SD,Alive);
claim(SD,Weakagree);

claim(SD,Niagree);
claim(SD,Nisynch);
    }
}
