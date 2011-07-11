<?php

namespace s9e\Acl\Tests;

use s9e\Acl\Acl;
use s9e\Acl\Role;

include_once __DIR__ . '/../src/Acl.php';
include_once __DIR__ . '/../src/Role.php';

class RoleTest extends \PHPUnit_Framework_TestCase
{
	public function testSimpleRole()
	{
		$admin = new Role('admin');
		$admin->allow('administer');
		$admin->addRule('administer', 'grant', 'supervise');

		$user  = new Acl;

		$this->assertFalse($user->isAllowed('administer'));

		$user->addParent($admin);

		$this->assertTrue($user->isAllowed('administer'));
		$this->assertTrue($user->isAllowed('supervise'));
	}
}