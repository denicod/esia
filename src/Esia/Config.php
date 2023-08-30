<?php

namespace Esia;

use Esia\Exceptions\InvalidConfigurationException;

class Config
{
    private $clientId;
    private $redirectUrl;
    private $privateKeyPath;
    private $certPath;
    private $certSubjectName;

    private $portalUrl = 'http://esia-portal1.test.gosuslugi.ru/';
    private $tokenUrlPath = 'aas/oauth2/te';
    private $tokenUrlPath_V3 = 'aas/oauth2/v3/te';
    private $codeUrlPath = 'aas/oauth2/ac';
    private $codeUrlPath_V2 = 'aas/oauth2/v2/ac';
    private $personUrlPath = 'rs/prns';
    private $logoutUrlPath = 'idp/ext/Logout';
    private $privateKeyPassword = '';
    protected $ESIACertSHA1 = '01e6041097ccf5a26da1d75fdbb1e7aaee07bd2a'; // SHA1 хэш сертификата ЕСИА (openssl sha1 ./GOST\ 2012\ PROD.cer)

    private $scope = [
        'fullname',
        'birthdate',
        'gender',
        'email',
        'mobile',
        'id_doc',
        'snils',
        'inn',
    ];

    private $tmpPath = '/var/tmp';

    private $responseType = 'code';
    private $accessType = 'offline';

    private $token = '';
    private $oid = '';

    /**
     * Config constructor.
     *
     * @throws InvalidConfigurationException
     */
    public function __construct(array $config = [])
    {
        // Required params
        $this->clientId = $config['clientId'] ?? $this->clientId;
        if (!$this->clientId) {
            throw new InvalidConfigurationException('Please provide clientId');
        }

        $this->redirectUrl = $config['redirectUrl'] ?? $this->redirectUrl;
        if (!$this->redirectUrl) {
            throw new InvalidConfigurationException('Please provide redirectUrl');
        }

        $this->privateKeyPath = $config['privateKeyPath'] ?? $this->privateKeyPath;
        if (!$this->privateKeyPath) {
            throw new InvalidConfigurationException('Please provide privateKeyPath');
        }
        $this->certPath = $config['certPath'] ?? $this->certPath;
        if (!$this->certPath) {
            throw new InvalidConfigurationException('Please provide certPath');
        }

        $this->portalUrl = $config['portalUrl'] ?? $this->portalUrl;
        $this->tokenUrlPath = $config['tokenUrlPath'] ?? $this->tokenUrlPath;
        $this->codeUrlPath = $config['codeUrlPath'] ?? $this->codeUrlPath;
        $this->personUrlPath = $config['personUrlPath'] ?? $this->personUrlPath;
        $this->logoutUrlPath = $config['logoutUrlPath'] ?? $this->logoutUrlPath;
        $this->privateKeyPassword = $config['privateKeyPassword'] ?? $this->privateKeyPassword;
        $this->oid = $config['oid'] ?? $this->oid;
        $this->scope = $config['scope'] ?? $this->scope;
        if (!is_array($this->scope)) {
            throw new InvalidConfigurationException('scope must be array of strings');
        }

        $this->responseType = $config['responseType'] ?? $this->responseType;
        $this->accessType = $config['accessType'] ?? $this->accessType;
        $this->tmpPath = $config['tmpPath'] ?? $this->tmpPath;
        $this->token = $config['token'] ?? $this->token;
        $this->certSubjectName = $config['certSubjectName'] ?? $this->certSubjectName;
    }

    public function getPortalUrl(): string
    {
        return $this->portalUrl;
    }

    public function getPrivateKeyPath(): string
    {
        return $this->privateKeyPath;
    }

    public function getPrivateKeyPassword(): string
    {
        return $this->privateKeyPassword;
    }

    public function getCertPath(): string
    {
        return $this->certPath;
    }
    
    public function getOid(): string
    {
        return $this->oid;
    }

    public function setOid(string $oid): void
    {
        $this->oid = $oid;
    }

    public function getScope(): array
    {
        return $this->scope;
    }

    public function getScopeString(): string
    {
        return implode(' ', $this->scope);
    }

    public function getResponseType(): string
    {
        return $this->responseType;
    }

    public function getAccessType(): string
    {
        return $this->accessType;
    }

    public function getTmpPath(): string
    {
        return $this->tmpPath;
    }

    public function getToken(): ?string
    {
        return $this->token;
    }

    public function getToken_V3(string $code): string
    {
        $timestamp = $this->getTimeStamp();
        $state = $this->buildState();

        $this->signer = new SignerCPDataHash(
            $config->getCertPath(),
            $config->getPrivateKeyPath(),
            $config->getPrivateKeyPassword(),
            $config->getTmpPath()
        );

        $clientSecret = $this->signer->sign(
              $this->config->getClientId()
            . $this->config->getScopeString()
            . $timestamp
            . $state
            . $this->config->getRedirectUrl()
        );

        $body = [
            'client_id' => $this->config->getClientId(),
            'code' => $code,
            'grant_type' => 'authorization_code',
            'client_secret' => $clientSecret,
            'state' => $state,
            'redirect_uri' => $this->config->getRedirectUrl(),
            'scope' => $this->config->getScopeString(),
            'timestamp' => $timestamp,
            'token_type' => 'Bearer',
            'refresh_token' => $state,
            'client_certificate_hash' => $this->clientCertHash,
        ];

        $payload = $this->sendRequest(
            new Request(
                'POST',
                $this->config->getTokenUrl_V3(),
                [
                    'Content-Type' => 'application/x-www-form-urlencoded',
                ],
                http_build_query($body)
            )
        );

        $this->logger->debug('Payload: ', $payload);

        $token = $payload['access_token'];

        $chunks = explode('.', $token);
        $payload = json_decode($this->base64UrlSafeDecode($chunks[1]), true);
        $header = json_decode($this->base64UrlSafeDecode($chunks[0]), true);
        $_token_signature  = $this->base64UrlSafeDecode($chunks[2]);

        if ('JWT'==$header->typ) {
            $store = new \CPStore();            
            $store->Open(CURRENT_USER_STORE, "Users", STORE_OPEN_READ_ONLY); // используем хранилище Users
            $certs = $store->get_Certificates();
            $certlist = $certs->Find(CERTIFICATE_FIND_SHA1_HASH, $this->ESIACertSHA1, 0); // ищем в хранилище сертификат ЕСИА по его sha1 хэшу
            $cert = $certlist->Item(1);
            if (!$cert) {
                 throw new CannotReadCertificateException('Cannot read the certificate');
            }              
            
            $hd = new \CPHashedData();        
            $hd->set_DataEncoding(BASE64_TO_BINARY);
            switch ($header->alg) {
               case 'GOST3410_2012_256':
                   $hd->set_Algorithm(CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256);
                   break; 
               case 'GOST3410_2012_512':
                   $hd->set_Algorithm(CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_512);
                   break;             
               default:
                   throw new Exception('Invalid signature algorithm');    
            }
            $hd->Hash(base64_encode($chunks[0].'.'.$chunks[1]));        
            $rs = new \CPRawSignature();
            $rs->VerifyHash($hd, bin2hex(strrev($_token_signature)), $cert);

            //если попали на эту строчку, значит подпись валидная. Иначе бы уже было вызвано исключение.
            $this->config->setOid($payload['urn:esia:sbj_id']);  
            $this->config->setToken($token);
        } // JWT token

        return $token;
    }

    public function setToken(string $token): void
    {
        $this->token = $token;
    }

    public function getClientId(): string
    {
        return $this->clientId;
    }

    public function getRedirectUrl(): string
    {
        return $this->redirectUrl;
    }

    /**
     * Return an url for request to get an access token
     */
    public function getTokenUrl(): string
    {
        return $this->portalUrl . $this->tokenUrlPath;
    }

    /**
     * Return an url for request to get an access token
     */
    public function getTokenUrl_V3(): string
    {
        return $this->portalUrl . $this->tokenUrlPath_V3;
    }

    public function getClientCertSubject(): string
    {
        return $this->certSubjectName;
    }
    /**
     * Return an url for request to get an authorization code
     */
    public function getCodeUrl(): string
    {
        return $this->portalUrl . $this->codeUrlPath;
    }

    /**
     * Return an url for request to get an authorization code
     */
    public function getCodeUrl_V2(): string
    {
        return $this->portalUrl . $this->codeUrlPath_V2;
    }

    /**
     * @return string
     * @throws InvalidConfigurationException
     */
    public function getPersonUrl(): string
    {
        if (!$this->oid) {
            throw new InvalidConfigurationException('Please provide oid');
        }
        return $this->portalUrl . $this->personUrlPath . '/' . $this->oid;
    }

    /**
     * Return an url for logout
     */
    public function getLogoutUrl(): string
    {
        return $this->portalUrl . $this->logoutUrlPath;
    }
}
