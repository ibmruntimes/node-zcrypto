//USERIDX  JOB X,X,USER=USERID,REGION=4M,MSGCLASS=H,TIME=1440  
//*                                                              
/*JOBPARM S=*                                                    
//S1       EXEC PGM=IKJEFT01                                     
//SYSTSPRT DD SYSOUT=*                                           
//SYSPRINT DD SYSOUT=*                                           
//SYSTSIN  DD *                                                  

RACDCERT GENCERT CERTAUTH +
SUBJECTSDN( +
  CN('HOSTNAME') +
  C('CA') +
  SP('Ontario') +
  L('Toronto') +
  O('IBM') +
  OU('Systems') +
) +
ALTNAME( +
  EMAIL('myemail@email2.com') +
  DOMAIN('email2.com') +
) +
WITHLABEL('CACert') +
NOTAFTER(DATE(2030/01/01))
                                                                  
RACDCERT GENCERT ID(USERID) +
SUBJECTSDN( +
  CN('ZOSCAN2B') +
  C('CA') +
  SP('Ontario') +
  L('Toronto') +
  O('IBM') +
  OU('Systems') +
) +
ALTNAME( +
  EMAIL('myemail@email.com') +
  DOMAIN('email.com') +
) +
WITHLABEL('ServerCert') +
SIGNWITH(CERTAUTH LABEL('CACert')) +
NOTAFTER(DATE(2030/01/01))

RACDCERT ADDRING(MYRING) ID(USERID)                              
                                                                   
RACDCERT ID(USERID) CONNECT(CERTAUTH LABEL('CACert') +            
     RING(MYRING))                                                
                                                                   
RACDCERT ID(USERID) CONNECT(ID(USERID) LABEL('ServerCert') +     
     RING(MYRING) USAGE(PERSONAL) DEFAULT)                        
