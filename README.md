# Sapienza SPID - sapspid
sapspid è composto da un insieme di servizi RestFULL che permettono l’astrazione dallo standard SAML2, consentendo al service provider di gestire l’intero ciclo di autenticazione SPID in modo trasparente e facilmente configurabile.
## COME FUNZIONA
sapspid è un middleware che si interpone tra il service provider (SP) e l’identity provider (IdP). Il tipico flusso di richiesta di accesso è il seguente:

1 - L’utente richiede accesso tramite SPID ad un servizio del service.provider (SP);
2- Il SP, contatta sapspid attraverso le sue API;
3- sapspid genera la richiesta SAML e dirige il browser dell’utente verso la pagina dell’identity provider (IdP) scelto utilizzando uno dei 2 metodi (BINDING HTTP REDIRECTo BINDING HTTP POST);
4- La risposta dell’IdP (SAML response), a seguito dell’autenticazione dell’utente, viene catturata da sapspid, verificata ed inviata al SP che la elabora e determina l’esito della richiesta di accesso.

Tutte le API di sapspid sono di tipo RestFull ed essendo basate su messaggi JSON, rendono più semplice l’implementazione da parte del SP. Il valore aggiunto di sapspid è racchiuso nella possibilità di configurare ogni parametro della transazione fra utente <–> SP <–> IdP. Si possono aggiungere IdP in modo trasparente, configurare le URL di callback chiamate dagli IdP per inoltrare la SAML response e configurare tutti gli elementi della SAML request che sono al centro della transazione SPID. Tutte le configurazioni sono archiviate in un DB PostgreSQL
Una volta configurato, sapspid è in grado di pubblicare i metadati SAML del SP.
## SICUREZZA
Poiché sapspid è un middleware, può generare problemi di sicurezza dovuti al fatto che, nel normale processo di trusting che avviene fra SP e IdP, si inserisce un nuovo attore. sapspid è un intermediario che per conto del SP si occupa della generazione della SAML request e del successivo inoltro della SAML response al SP. In particolare:

1.	SP -> ES: SP chiede ad sapspid di generare per lui la SAML Request;
2.	sapspid -> IdP: sapspid invia la SAML Request all’IdP scelto dall’Utente;
3.	Idp -> sapspid: l’utente si autentica presso IdP e quest’ultimo invia la SAML Response a sapspid;
4.	sapspid -> SP: ES elabora la SAML Response ed invoca un servizio del SP per fornire le informazioni di autenticazione.

L’SP concede accesso ai propri servizi a seguito dell’invio da parte di ES di un messaggio di corretta autenticazione dell’utente su un IdP (SAML response). Poiché le fasi 1 e 4 non sono a conoscenza delle fasi 2 e 3, è possibile che un terzo non autorizzato invii ad SP un messaggio “fake” di autenticazione ed ottenga accesso illegale ai servizi di SP.
Affinché SP possa essere sicuro del mittente e che il messaggio ricevuto derivi da una reale richiesta iniziata nella fase 1, è sufficiente l’utilizzo di un opportuno “token” generato da sapspid nella fase 3 (quando sapspid riceve la SAML response dell’IdP) e inviato da sapspid a SP nella fase 4. 
Un terzo che, cercasse di inviare un messaggio “fake” a SP non potrebbe generare un token valido permettendo a SP di rigettare la richiesta di accesso. 
## REQUISITI
Sapspid è scritto in Python ed utilizza un Database Postgresql per meomoriazzare le asserzioni SAML ed i parametridi configurazione del SP.
In particolare:
* Python 3.6
* tornado 4.5.1
* xmlsec 1.1.0
* psycopg2 2.7.1
* ujson 1.35 o in alternativa simplejson 3.11.1
* PyJWT 1.5.2
* jsonschema 2.6.0
* cryptography 1.7.2
* python3-saml 1.2.6
* defusedxml 0.5.0
* PostgreSQL 9.6
* PostgreSQL PL/Python
Attualemnte sapspud è installato su un sistema FreeBSD 11
# INSTALLAZIONE
Scaricare la release 1.0 di sapspid e copiarla in un path del server: /path/to/sapspid
Modifucare i fole di configurazione locale:
* `server_local.ini`. **NOTA non modificare il numero il parametro num_processes.** Per poter gestire correttamente il pool di connessioni in modalit multi threaded il processo deve essere 1 solo.
* `jwtoken_local.ini`. Configurare corretatemnte i parametri di connessione al master ed allo slave DB. Nel caso in cui si disponga di una sola istanza di PostgreSQL utilizzare le stesse configurazini sia per il Matser che per lo Slave. **NOTA max_conn deve essere uguale a min_conn per poter utulizzare correttaemnte le PREPARED STATEMENTS**
* `easyspid_local.ini`. Configurare corretatemnte i parametri di connessione al master ed allo slave DB. Nel caso in cui si disponga di una sola istanza di PostgreSQL utilizzare le stesse configurazini sia per il Matser che per lo Slave. **NOTA max_conn deve essere uguale a min_conn per poter utulizzare correttaemnte le PREPARED STATEMENTS**
* `logging_local.ini`
Il comando per far partire sapspid è:
> cd /path/to/sapspid && python server.py -c server_local.py 
# CONFIGURAZIONE
La configurazione di sapspid avviene modificando opportune tabelle del DB ed opportuni file dell'applicativo.
L'intero schema del DB è si trova [sapspid DBschema](http://spid.uniroma1.it/api/doc/SchemaDb/index.html).
## SP settings
Le impostazioni del service provider si trovano nelle tabelle:
* [providers](http://spid.uniroma1.it/api/doc/SchemaDb/saml/tables/providers.html)
* [settings](http://spid.uniroma1.it/api/doc/SchemaDb/saml/tables/settings.html). Modifcarte i json delle colonne settings ed advanced_settings riposratndo i dati del service provider
* [signatures](http://spid.uniroma1.it/api/doc/SchemaDb/saml/tables/signatures.html). Inserire le chaivi pubbliche degli Idp e quelle pubbliche e private degli SP. Il sistema calcola utomaticamente le fingerprint in base fingerprintalg scelto.
* [services](http://spid.uniroma1.it/api/doc/SchemaDb/saml/tables/services.html). Inserire i relaystate per il service provider.
## IdP settings
Le impostazioni degli Idp si trovano nelle tabelle:
* [providers](http://spid.uniroma1.it/api/doc/SchemaDb/saml/tables/providers.html)
* [metadata](http://spid.uniroma1.it/api/doc/SchemaDb/saml/tables/metadata.html). Copiare nella colonnna xml il metadata dell'Identity Provider

