<?php

namespace s9e\TextFormatter\Tests;

use PHPUnit_Framework_TestCase;
use s9e\Acl\Builder;

/**
* @covers s9e\Acl\Reader
*/
class ReaderTest extends PHPUnit_Framework_TestCase
{
	/**
	* @testdox isAllowed('foo') returns true if allow('foo') was called
	*/
	public function testGlobalAllowed()
	{
		$builder = new Builder;
		$builder->allow('foo');
		$acl = $builder->getReader();
		$this->assertTrue($acl->isAllowed('foo'));
	}

	/**
	* @testdox isAllowed('foo') returns false if deny('foo') was called
	*/
	public function testGlobalDenied()
	{
		$builder = new Builder;
		$builder->deny('foo');
		$acl = $builder->getReader();
		$this->assertFalse($acl->isAllowed('foo'));
	}

	/**
	* @testdox isAllowed('foo') returns false if no permissions were set
	*/
	public function testGlobalNoPermissions()
	{
		$builder = new Builder;
		$acl = $builder->getReader();
		$this->assertFalse($acl->isAllowed('foo'));
	}

	/**
	* @testdox isAllowed('foo', ['cat' => 1]) returns true if allow('foo') was called
	*/
	public function testGlobalAllowsLocal()
	{
		$builder = new Builder;
		$builder->allow('foo');
		$acl = $builder->getReader();
		$this->assertTrue($acl->isAllowed('foo', ['cat' => 1]));
	}

	/**
	* @testdox isAllowed('foo', ['cat' => 1]) returns true if allow('foo', ['cat' => 1]) was called
	*/
	public function testLocalAllowed()
	{
		$builder = new Builder;
		$builder->allow('foo', ['cat' => 1]);
		$acl = $builder->getReader();
		$this->assertTrue($acl->isAllowed('foo', ['cat' => 1]));
	}

	/**
	* @testdox isAllowed('foo', ['x'=>1,'y'=>2]) returns true if allow('foo',['x'=>1,'y'=>2]) was called
	*/
	public function testLocalAllowedMultipleDimensions()
	{
		$builder = new Builder;
		$builder->allow('foo', ['x' => 1, 'y' => 2]);
		$acl = $builder->getReader();
		$this->assertTrue($acl->isAllowed('foo', ['x' => 1, 'y' => 2]));
	}

	/**
	* @testdox isAllowed('foo', ['x'=>1,'y'=>2]) returns true if allow('foo',['x'=>1]) was called
	*/
	public function testLocalAllowedExtraDimensions()
	{
		$builder = new Builder;
		$builder->allow('foo', ['x' => 1]);
		$acl = $builder->getReader();
		$this->assertTrue($acl->isAllowed('foo', ['x' => 1, 'y' => 2]));
	}

	/**
	* @testdox isAllowed('foo', ['x' => WILDCARD]) returns true if allow('foo', ['x' => 1]) was called
	*/
	public function testLocalWildcard()
	{
		$builder = new Builder;
		$builder->allow('foo', ['x' => 1]);
		$acl = $builder->getReader();
		$this->assertTrue($acl->isAllowed('foo', ['x' => $acl::WILDCARD]));
	}

	/**
	* @testdox isAllowed('foo', WILDCARD) returns true if allow('foo', ['x' => 1]) was called
	*/
	public function testGlobalWildcard()
	{
		$builder = new Builder;
		$builder->allow('foo', ['x' => 1]);
		$acl = $builder->getReader();
		$this->assertTrue($acl->isAllowed('foo', $acl::WILDCARD));
	}

	/**
	* @testdox isAllowed('foo', [WILDCARD => 1]) returns true if allow('foo', ['x' => 1]) was called
	*/
	public function testWildcardScope()
	{
		$builder = new Builder;
		$builder->allow('foo', ['x' => 1]);
		$acl = $builder->getReader();
		$this->assertTrue($acl->isAllowed('foo', [$acl::WILDCARD => 1]));
	}

	/**
	* @testdox isAllowed('foo', [WILDCARD => 2]) returns false if allow('foo', ['x' => 1]) was called
	*/
	public function testWildcardScopeMiss()
	{
		$builder = new Builder;
		$builder->allow('foo', ['x' => 1]);
		$acl = $builder->getReader();
		$this->assertFalse($acl->isAllowed('foo', [$acl::WILDCARD => 2]));
	}

	/**
	* @testdox isAllowed('foo', ['x' => 1, WILDCARD => WILDCARD]) returns true if allow('foo', ['x' => 1, 'y' => 2]) was called
	*/
	public function testWildcardScopePartial()
	{
		$builder = new Builder;
		$builder->allow('foo', ['x' => 1, 'y' => 2]);
		$acl = $builder->getReader();
		$this->assertTrue($acl->isAllowed('foo', ['x' => 1, $acl::WILDCARD => $acl::WILDCARD]));
	}

	/**
	* @testdox isAllowed() rejects a scalar value used as scope
	* @expectedException InvalidArgumentException
	* @expectedExceptionMessage Scope must be an array or an instance of s9e\Acl\Resource
	*/
	public function testScalarScope()
	{
		$builder = new Builder;
		$builder->allow('foo', ['id' => 123]);
		$builder->getReader()->isAllowed('foo', 123);
	}

	/**
	* @testdox isAllowed() accepts an instance of s9e\Acl\Resource as scope if its getAclScope() method returns an array
	*/
	public function testResourceScope()
	{
		$builder = new Builder;
		$builder->allow('foo', ['id' => 123]);
		$reader = $builder->getReader();

		$resource = $this->getMock('s9e\\Acl\\Resource');
		$resource->expects($this->once())
		         ->method('getAclAttributes')
		         ->will($this->returnValue(['id' => 123]));
		$this->assertTrue($reader->isAllowed('foo', $resource));

		$resource = $this->getMock('s9e\\Acl\\Resource');
		$resource->expects($this->once())
		         ->method('getAclAttributes')
		         ->will($this->returnValue(['id' => 456]));
		$this->assertFalse($reader->isAllowed('foo', $resource));
	}
}