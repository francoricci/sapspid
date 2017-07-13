# Sapienza SPID - sapspid

sapspid è composto da un insieme di servizi RestFULL che permettono l’astrazione dallo standard SAML2, consentendo al service provider di gestire l’intero ciclo di autenticazione SPID in modo trasparente e facilmente configurabile.

## EASYSPID – COME FUNZIONA
EasySPID è un middleware che si interpone tra il service provider (SP) e l’identity provider (IdP). Il tipico flusso di richiesta di accesso è il seguente:

1 - L’utente richiede accesso tramite SPID ad un servizio del service.provider (SP);
2- Il SP, contatta EasySPID attraverso le sue API;
3- EasySPID genera la richiesta SAML e dirige il browser dell’utente verso la pagina dell’identity provider (IdP) scelto utilizzando uno dei 2 metodi (BINDING HTTP REDIRECTo BINDING HTTP POST);
4- La risposta dell’IdP (SAML response), a seguito dell’autenticazione dell’utente, viene catturata da EasySPID, verificata ed inviata al SP che la elabora e determina l’esito della richiesta di accesso.

Tutte le API di EasySPID sono di tipo RestFull ed essendo basate su messaggi JSON, rendono più semplice l’implementazione da parte del SP. Il valore aggiunto di EasySPID è racchiuso nella possibilità di configurare ogni parametro della transazione fra utente <–> SP <–> IdP. Si possono aggiungere IdP in modo trasparente, configurare le URL di callback chiamate dagli IdP per inoltrare la SAML response e configurare tutti gli elementi della SAML request che sono al centro della transazione SPID. Si possono attivare notifiche per gli amministratori e visualizzare i log delle transazioni. Tutte le configurazioni sono archiviate in un DB.  
Una volta configurato, EasySPID è in grado di pubblicare i metadati SAML ad uso di tutti gli IdP.
