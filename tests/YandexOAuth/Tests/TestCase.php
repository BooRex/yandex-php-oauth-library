<?php
/**
 * @namespace
 */
namespace YandexOAuth\Tests;

use YandexOAuth;
use ReflectionClass;
use PHPUnit\Framework\TestCase as PHPUnitFrameworkTestCase;

/**
 * ControllerTestCase
 *
 * @package  YandexOAuth\Tests
 *
 * @author   Anton Shevchuk
 * @created  07.08.13 12:01
 */
class TestCase extends PHPUnitFrameworkTestCase
{
    /**
     * @param string|object $classNameOrObject
     * @param string $name
     * @return \ReflectionMethod
     * @throws \ReflectionException
     */
    protected static function getNotAccessibleMethod($classNameOrObject, $name) {
        $class = new ReflectionClass($classNameOrObject);
        $method = $class->getMethod($name);
        $method->setAccessible(true);
        return $method;
    }
}
