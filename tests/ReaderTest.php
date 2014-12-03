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
}