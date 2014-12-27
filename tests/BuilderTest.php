<?php

namespace s9e\Acl\Tests;

use PHPUnit_Framework_TestCase;
use s9e\Acl\Builder;

/**
* @covers s9e\Acl\Builder
*/
class BuilderTest extends PHPUnit_Framework_TestCase
{
	/**
	* @testdox allow() rejects an empty string used as action
	* @expectedException InvalidArgumentException
	* @expectedExceptionMessage Action cannot be an empty string
	*/
	public function testEmptyAction()
	{
		$builder = new Builder;
		$builder->allow('', []);
	}

	/**
	* @testdox allow() rejects an empty string used as dimension
	* @expectedException InvalidArgumentException
	* @expectedExceptionMessage Scope dimensions must have a name
	*/
	public function testScopeDimensionEmpty()
	{
		$builder = new Builder;
		$builder->allow('foo', ['' => 'x']);
	}

	/**
	* @testdox allow() rejects an empty string used as scope value
	* @expectedException InvalidArgumentException
	* @expectedExceptionMessage Scope value for x cannot be empty
	*/
	public function testScopeValueEmpty()
	{
		$builder = new Builder;
		$builder->allow('foo', ['x' => '']);
	}

	/**
	* @testdox allow() rejects float as scope value
	* @expectedException InvalidArgumentException
	* @expectedExceptionMessage Invalid type for x scope: integer or string expected, double given
	*/
	public function testScopeValueFloat()
	{
		$builder = new Builder;
		$builder->allow('foo', ['x' => 2.2]);
	}

	/**
	* @testdox allow() rejects boolean as scope value
	* @expectedException InvalidArgumentException
	* @expectedExceptionMessage Invalid type for x scope: integer or string expected, boolean given
	*/
	public function testScopeValueBoolean()
	{
		$builder = new Builder;
		$builder->allow('foo', ['x' => true]);
	}

	/**
	* @testdox allow() can be called without a scope
	*/
	public function testAllowNoScope()
	{
		$builder = new Builder;
		$builder->allow('foo');
	}

	/**
	* @testdox deny() can be called without a scope
	*/
	public function testDenyNoScope()
	{
		$builder = new Builder;
		$builder->deny('foo');
	}

	/**
	* @testdox allow() defaults to the global scope if none is provided
	*/
	public function testAllowNoScopeDefaultGlobal()
	{
		$builder = new Builder;
		$builder->allow('foo');
		$this->assertEquals(['foo' => true], $builder->getReaderConfig());
	}

	/**
	* @testdox deny() defaults to the global scope if none is provided
	*/
	public function testDenyNoScopeDefaultGlobal()
	{
		$builder = new Builder;
		$builder->allow('foo');
		$this->assertEquals(['foo' => true], $builder->getReaderConfig());
	}

	/**
	* @testdox allow() rejects a scalar value used as scope
	* @expectedException InvalidArgumentException
	* @expectedExceptionMessage Scope must be an array or an instance of s9e\Acl\Resource
	*/
	public function testScalarScope()
	{
		$builder = new Builder;
		$builder->allow('foo', 123);
	}

	/**
	* @testdox allow() accepts an instance of s9e\Acl\Resource as scope if its getAclScope() method returns an array
	*/
	public function testResourceScope()
	{
		$resource = $this->getMock('s9e\\Acl\\Resource');
		$resource->expects($this->once())
		         ->method('getAclScope')
		         ->will($this->returnValue(['id' => 123]));

		$builder = new Builder;
		$builder->allow('foo', $resource);

		$this->assertEquals(
			[
				'foo' => [
					"\6",
					[],
					['id'  => ['' => 1, 123 => 2]]
				]
			],
			$builder->getReaderConfig()
		);
	}

	/**
	* @testdox addRule() rejects rule "foo"
	* @expectedException InvalidArgumentException
	* @expectedExceptionMessage Unsupported rule 'foo'
	*/
	public function testInvalidRule()
	{
		$builder = new Builder;
		$builder->addRule('src', 'foo', 'trg');
	}

	/**
	* @testdox addRule() rejects empty string as source action
	* @expectedException InvalidArgumentException
	* @expectedExceptionMessage Action cannot be an empty string
	*/
	public function testRuleEmptySrcAction()
	{
		$builder = new Builder;
		$builder->addRule('', 'grant', 'trg');
	}

	/**
	* @testdox addRule() rejects empty string as source action
	* @expectedException InvalidArgumentException
	* @expectedExceptionMessage Action cannot be an empty string
	*/
	public function testRuleEmptyTrgAction()
	{
		$builder = new Builder;
		$builder->addRule('src', 'grant', '');
	}

	/**
	* @testdox addRule() can be called even if no permission is set
	*/
	public function testAddRuleNoPerm()
	{
		$builder = new Builder;
		$builder->addRule('src', 'grant', 'trg');
	}

	/**
	* @testdox getReader() returns an instance of s9e\Acl\Reader
	*/
	public function testGetReader()
	{
		$builder = new Builder;
		$this->assertInstanceOf('s9e\\Acl\\Reader', $builder->getReader());
	}

	/**
	* @testdox getReaderConfig() tests
	* @dataProvider getGetReaderConfigTests
	*/
	public function testGetReaderConfig($permissions, $rules, $expected)
	{
		$builder = new Builder;
		foreach ($permissions as $action => $settings)
		{
			foreach ($settings as $setting)
			{
				list($methodName, $scope) = $setting;
				$builder->$methodName($action, $scope);
			}
		}
		foreach ($rules as $rule)
		{
			list($ruleName, $srcAction, $trgAction) = $rule;
			$builder->addRule($ruleName, $srcAction, $trgAction);
		}

		$this->assertEquals($expected, $builder->getReaderConfig());
	}

	public function getGetReaderConfigTests()
	{
		return [
			[
				['publish' => [['allow', []]]],
				[],
				[
					'publish' => true
				]
			],
			[
				['publish' => [['deny', []]]],
				[],
				[]
			],
			[
				['publish' => [['allow', []], ['deny', []]]],
				[],
				[]
			],
			[
				['publish' => [['allow', ['cat' => 1]]]],
				[],
				[
					'publish' => ["\6", [], ['cat' => ['' => 1, 1 => 2]]]
				]
			],
			[
				[
					'publish' => [['allow', []]],
					'edit'    => [['allow', []]]
				],
				[
					['edit', 'require', 'publish']
				],
				[
					'publish' => true,
					'edit'    => true
				]
			],
			[
				[
					'publish' => [['allow', []]],
					'edit'    => [['allow', ['cat' => 123]]]
				],
				[
					['edit', 'require', 'publish']
				],
				[
					'publish' => [
						"\016",
						['publish' => 1],
						['cat' => ['' => 1, 123 => 2]]
					],
					'edit' => [
						"\016",
						['publish' => 1],
						['cat' => ['' => 1, 123 => 2]]
					]
				]
			],
			[
				[
					'edit'    => [['allow', ['cat' => 123]]]
				],
				[
					['edit', 'grant', 'publish']
				],
				[
					'publish' => [
						"\6",
						[],
						['cat' => ['' => 1, 123 => 2]]
					],
					'edit' => [
						"\6",
						[],
						['cat' => ['' => 1, 123 => 2]]
					]
				]
			],
			[
				[
					'edit' => [['allow', ['cat' => 123]]]
				],
				[
					['publish', 'grant', 'edit']
				],
				[
					'edit' => [
						"\6",
						[],
						['cat' => ['' => 1, 123 => 2]]
					]
				]
			],
			[
				[
					'edit'    => [['allow', ['cat' => 123]]],
					'publish' => [['allow', []]]
				],
				[],
				[
					'edit' => [
						"\6",
						[],
						['cat' => ['' => 1, 123 => 2]]
					],
					'publish' => true
				]
			],
		];
	}
}