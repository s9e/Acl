<?php

namespace s9e\Acl\Tests;

use s9e\Acl\Acl;
use s9e\Acl\Role;
use s9e\Acl\RoleCache;

include_once __DIR__ . '/../src/Acl.php';
include_once __DIR__ . '/../src/Role.php';
include_once __DIR__ . '/../src/RoleCache.php';

class RoleCacheTest extends \PHPUnit_Framework_TestCase
{
	public function testSimpleRole()
	{
		$acl = new Acl;
		$this->assertFalse($acl->isAllowed('administer'));
		$acl->addParent($this->roleCache->get('admin'));
		$this->assertTrue($acl->isAllowed('administer'));
	}

	/**
	* @expectedException \InvalidArgumentException
	*/
	public function testAddDoesNotOverwriteRolesByDefault()
	{
		$this->roleCache->add(new Role('admin'));
	}

	/**
	* @depends testSimpleRole
	*/
	public function testCachedRolesCanBeOverwritten()
	{
		$this->roleCache->add(new Role('admin'), true);

		$acl = new Acl;
		$this->assertFalse($acl->isAllowed('administer'));
		$acl->addParent($this->roleCache->get('admin'));
		$this->assertFalse($acl->isAllowed('administer'));
	}

	/**
	* @expectedException \InvalidArgumentException
	*/
	public function testGetOnInexistentRoleThrowsAnException()
	{
		$this->roleCache->get('inexistent');
	}

	public function testExists()
	{
		$this->assertTrue($this->roleCache->exists('admin'));
	}

	/**
	* @depends testExists
	*/
	public function testClear()
	{
		$this->roleCache->clear();
		$this->assertFalse($this->roleCache->exists('admin'));
	}

	/**
	* @depends testExists
	*/
	public function testRemove()
	{
		$this->roleCache->add(new Role('foo'));

		$this->roleCache->remove('admin');
		$this->assertFalse($this->roleCache->exists('admin'));
		$this->assertTrue($this->roleCache->exists('foo'));
	}

	public function setUp()
	{
		$this->roleCache = new RoleCache;

		$admin = new Role('admin');
		$admin->allow('administer');

		$this->roleCache->add($admin);
	}
}