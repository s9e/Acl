<?php

namespace s9e\Acl\Tests;

use s9e\Acl\Acl;
use s9e\Acl\Wildcard;

include_once __DIR__ . '/../src/Acl.php';
include_once __DIR__ . '/../src/Wildcard.php';

class BasicTest extends \PHPUnit_Framework_TestCase
{
	public function testOneGlobalPerm()
	{
		$acl = new Acl;
		$acl->allow('foo');

		$this->assertTrue($acl->isAllowed('foo'));
	}

	public function testMultiGlobalPerms()
	{
		$acl = new Acl;
		$acl->allow('foo');
		$acl->deny('bar');

		$this->assertTrue($acl->isAllowed('foo'));
		$this->assertFalse($acl->isAllowed('bar'));
	}

	public function testUnknownPermsReturnFalse()
	{
		$acl = new Acl;
		$acl->allow('foo');

		$this->assertFalse($acl->isAllowed('bar'));
	}

	public function testDenyOverridesAllow()
	{
		$acl = new Acl;
		$acl->deny('foo');
		$acl->allow('foo');

		$this->assertFalse($acl->isAllowed('foo'));
	}

	public function testReaderCanBeSerializedWithoutLosingStuff()
	{
		$acl = new Acl;
		$acl->allow('foo');

		$reader  = $acl->getReader();
		$reader2 = unserialize(serialize($reader));

		$this->assertEquals($reader, $reader2);
	}

	/**
	* @expectedException \InvalidArgumentException
	*/
	public function testReaderRejectsNonArrayScope()
	{
		$acl = new Acl;
		$acl->allow('foo');

		$acl->isAllowed('foo', 123);
	}

	/**
	* @expectedException \InvalidArgumentException
	*/
	public function testAclRejectsNonArrayScope()
	{
		$acl = new Acl;
		$acl->allow('foo', 123);
	}

	/**
	* @expectedException \InvalidArgumentException
	*/
	public function testAclThrowsAnExceptionOnInvalidScopeValues()
	{
		$acl = new Acl;
		$acl->allow('foo', array('scope' => null));
	}

	public function testAclAllowIsChainable()
	{
		$acl = new Acl;
		$this->assertSame($acl, $acl->allow('foo'));
	}

	public function testAclDenyIsChainable()
	{
		$acl = new Acl;
		$this->assertSame($acl, $acl->deny('foo'));
	}

	public function testAclAddRuleIsChainable()
	{
		$acl = new Acl;
		$this->assertSame($acl, $acl->addRule('foo', 'grant', 'bar'));
	}

	public function testAclImportIsChainable()
	{
		$acl = new Acl;
		$this->assertSame($acl, $acl->addParent(new Acl));
	}

	public function testAclAcceptsBooleanScopeValues()
	{
		$acl = new Acl;
		$acl->allow('foo', array('scope' => true));
		$acl->allow('bar', array('scope' => false));
	}

	/**
	* @depends testAclAcceptsBooleanScopeValues
	*/
	public function testReaderWorksWithBooleanScopeValues()
	{
		$acl = new Acl;
		$acl->allow('foo', array('scope' => true));
		$acl->allow('bar', array('scope' => false));

		$this->assertTrue($acl->isAllowed('foo', array('scope' => true)));
		$this->assertFalse($acl->isAllowed('foo', array('scope' => false)));
		$this->assertFalse($acl->isAllowed('bar', array('scope' => true)));
		$this->assertTrue($acl->isAllowed('bar', array('scope' => false)));
	}

	public function testAclAcceptsFloatScopeValues()
	{
		$acl = new Acl;
		$acl->allow('foo', array('scope' => 1 / 3));
		$acl->allow('bar', array('scope' => 0.5));
	}

	/**
	* @depends testAclAcceptsFloatScopeValues
	*/
	public function testReaderWorksWithFloatScopeValues()
	{
		$acl = new Acl;
		$acl->allow('foo', array('scope' => 1 / 3));
		$acl->allow('bar', array('scope' => 0.5));

		$this->assertTrue($acl->isAllowed('foo', array('scope' => 1 / 3)));
		$this->assertTrue($acl->isAllowed('bar', array('scope' => 0.5)));
		$this->assertFalse($acl->isAllowed('bar', array('scope' => 0)));
		$this->assertFalse($acl->isAllowed('bar', array('scope' => 1)));
	}

	public function testAclDoesNotReturnStaleResultsAfterAllow()
	{
		$acl = new Acl;
		$this->assertFalse($acl->isAllowed('foo'));
		$acl->allow('foo');
		$this->assertTrue($acl->isAllowed('foo'));
	}

	public function testAclDoesNotReturnStaleResultsAfterAddRule()
	{
		$acl = new Acl;
		$acl->allow('foo');
		$this->assertTrue($acl->isAllowed('foo'));
		$acl->addRule('foo', 'require', 'bar');
		$this->assertFalse($acl->isAllowed('foo'));
	}

	public function testChildrenAclAreInvalidated()
	{
		$parent = new Acl;
		$parent->allow('foo');

		$child = new Acl;
		$child->addParent($parent);

		$grandchild = new Acl;

		$this->assertFalse($grandchild->isAllowed('foo'));
		$grandchild->addParent($child);
		$this->assertTrue($grandchild->isAllowed('foo'));
		$parent->deny('foo');
		$this->assertFalse($grandchild->isAllowed('foo'));
	}

	public function testAdditionalScopeIsAddedToScopeByReader()
	{
		$acl = new Acl;

		// allow post #2 to be read from far (it's not like tests are supposed to make sense)
		$acl->allow('read', array('post.id' => 2, 'from' => 'far'));

		// this query asks "can post #2 be read from everywhere?"
		$this->assertFalse($acl->isAllowed('read', array('post.id' => 2)));

		// this query asks "can post #2 be read from anywhere?"
		$this->assertTrue($acl->isAllowed('read', array('post.id' => 2), new Wildcard));
	}

	public function testAdditionalScopeDoesNotOverwriteTheOriginalScope()
	{
		$acl = new Acl;
		$acl->allow('read', array('post.id' => 2));

		$this->assertFalse($acl->isAllowed('read', array('post.id' => 3), array('post.id' => 2)));
		$this->assertTrue($acl->isAllowed('read', array('post.id' => 2), array('post.id' => 3)));
	}
}