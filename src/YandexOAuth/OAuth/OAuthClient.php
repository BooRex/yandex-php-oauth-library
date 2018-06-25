<?php
/**
 * yandex-php-oauth-library PHP Library
 *
 * @copyright NIX Solutions Ltd.
 * @link https://github.com/boorex/yandex-php-oauth-library
 */

/**
 * @namespace
 */
namespace YandexOAuth\OAuth;

use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\RequestException;
use YandexOAuth\Common\AbstractServiceClient;
use YandexOAuth\OAuth\Exception\AuthRequestException;
use YandexOAuth\OAuth\Exception\AuthResponseException;

/**
 * Class OAuthClient implements yandex-php-oauth-library OAuth protocol
 *
 * @package  YandexOAuth\OAuth
 *
 * @author   Eugene Zabolotniy <realbaziak@gmail.com>
 * @created  29.08.13 12:07
 */
class OAuthClient extends AbstractServiceClient
{
    /*
     * Authentication types constants
     *
     * The "code" type means that the application will use an intermediate code to obtain an access token.
     * The "token" type will result a user is redirected back to the application with an access token in a URL
     */
    const CODE_AUTH_TYPE = 'code';
    const TOKEN_AUTH_TYPE = 'token';

    /**
     * @var string
     */
    private $clientId = '';

    /**
     * @var string
     */
    private $clientSecret = '';

    /**
     * @var string
     */
    protected $serviceDomain = 'oauth.yandex.ru';

    /**
     * @param string $clientId
     * @param string $clientSecret
     */
    public function __construct($clientId = '', $clientSecret = '')
    {
        $this->setClientId($clientId);
        $this->setClientSecret($clientSecret);
    }

    /**
     * @param string $clientId
     *
     * @return self
     */
    public function setClientId($clientId)
    {
        $this->clientId = $clientId;

        return $this;
    }

    /**
     * @return string
     */
    public function getClientId()
    {
        return $this->clientId;
    }

    /**
     * @param string $clientSecret
     *
     * @return self
     */
    public function setClientSecret($clientSecret)
    {
        $this->clientSecret = $clientSecret;

        return $this;
    }

    /**
     * @return string
     */
    public function getClientSecret()
    {
        return $this->clientSecret;
    }

    /**
     * @param string $type
     * @param string $state optional string
     *
     * @return string
     */
    public function getAuthUrl($type = self::CODE_AUTH_TYPE, $state = null)
    {
        $url = $this->getServiceUrl('authorize') . '?response_type=' . $type . '&client_id=' . $this->clientId;
        if ($state) {
            $url .= '&state=' . $state;
        }

        return $url;
    }

    /**
     * Sends a redirect to the yandex-php-oauth-library authentication page.
     *
     * @param bool $exit indicates whether to stop the PHP script immediately or not
     * @param string $type a type of the authentication procedure
     * @param string $state optional string
     * @return bool|void
     */
    public function authRedirect($exit = true, $type = self::CODE_AUTH_TYPE, $state = null)
    {
        header('Location: ' . $this->getAuthUrl($type, $state));

        return $exit ? exit() : true;
    }

    /**
     * Exchanges a temporary code for an access token.
     *
     * @param $code
     *
     * @throws AuthRequestException on a known request error
     * @throws AuthResponseException on a response format error
     * @throws RequestException on an unknown request error
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Exception
     *
     * @return self
     */
    public function requestAccessToken($code)
    {
        $client = $this->getClient();

        try {
            $response = $client->request(
                'POST',
                '/token',
                [
                    'auth' => [
                        $this->clientId,
                        $this->clientSecret
                    ],
                    'form_params' => [
                        'grant_type'    => 'authorization_code',
                        'code'          => $code,
                        'client_id'     => $this->clientId,
                        'client_secret' => $this->clientSecret
                    ]
                ]
            );
        } catch (ClientException $ex) {
            $result = $this->getDecodedBody($ex->getResponse()->getBody());

            if (is_array($result) && isset($result['error'])) {
                // handle a service error message
                $message = 'Service responsed with error code "' . $result['error'] . '".';

                if (isset($result['error_description']) && $result['error_description']) {
                    $message .= ' Description "' . $result['error_description'] . '".';
                }
                throw new AuthRequestException($message, 0, $ex);
            }

            // unknown error. not parsed error
            throw $ex;
        }

        try {
            $result = $this->getDecodedBody($response->getBody());
        } catch (\RuntimeException $ex) {
            throw new AuthResponseException('Server response can\'t be parsed', 0, $ex);
        }

        if (!is_array($result)) {
            throw new AuthResponseException('Server response has unknown format');
        }

        if (!isset($result['access_token'])) {
            throw new AuthResponseException('Server response doesn\'t contain access token');
        }

        $this->setAccessToken($result['access_token']);

        $lifetimeInSeconds = $result['expires_in'];

        $expireDateTime = new \DateTime();
        $expireDateTime->add(new \DateInterval('PT'.$lifetimeInSeconds.'S'));

        $this->setExpiresIn($expireDateTime);

        return $this;
    }

    /**
     * Exchange access token for a user data
     *
     * @param $accessToken
     *
     * @throws AuthRequestException
     * @throws AuthResponseException
     * @throws \GuzzleHttp\Exception\GuzzleException
     *
     * @return array|mixed|\SimpleXMLElement
     */
    public function getUserData($accessToken)
    {
        $client = $this->getClient();

        try {
            $response = $client->request(
                'GET',
                'https://login.yandex.ru/info',
                [
                    'query' => [
                        'format' => 'json',
                        'oauth_token' => $accessToken,
                    ],
                ]
            );
        } catch (ClientException $ex) {
            $result = $this->getDecodedBody($ex->getResponse()->getBody());

            if (is_array($result) && isset($result['error'])) {
                // handle a service error message
                $message = 'Service responsed with error code "' . $result['error'] . '".';

                if (isset($result['error_description']) && $result['error_description']) {
                    $message .= ' Description "' . $result['error_description'] . '".';
                }
                throw new AuthRequestException($message, 0, $ex);
            }

            // unknown error. not parsed error
            throw $ex;
        }

        try {
            $userData = $this->getDecodedBody($response->getBody());
        } catch (\RuntimeException $ex) {
            throw new AuthResponseException('Server response can\'t be parsed', 0, $ex);
        }

        if (!is_array($userData)) {
            throw new AuthResponseException('Server response has unknown format');
        }

        return $userData;
    }
}
