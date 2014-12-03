<?php

/**
* @package   s9e\Acl
* @copyright Copyright (c) 2010-2014 The s9e Authors
* @license   http://www.opensource.org/licenses/mit-license.php The MIT License
*/
namespace s9e\Acl;

class BitPacker
{
	/**
	* @var array Associative array using the first n characters of each string as keys, and the
	*            index of the corresponding string in $this->strings as values
	*/
	protected $heads;

	/**
	* @var integer[] Lengths of strings being merged
	*/
	protected $lengths;

	/**
	* @var string[] Strings being merged
	*/
	protected $strings;

	/**
	* @var array Associative array using the last n characters of each string as keys, and the
	*            index of the corresponding string in $this->strings as values
	*/
	protected $tails;

	/**
	* Merge an array strings into the shortest string possible
	*
	* Strings are expected to be made entirely of '0' and '1'. The result isn't guaranteed to be
	* optimal but it should be pretty close.
	*
	* @param  string[] $strings List of strings, each composed entirely of '0' and '1'
	* @return string
	*/
	public function merge(array $strings)
	{
		$this->strings = array_unique($strings);
		$this->lengths = array_map('strlen', $this->strings);

		$len = max($this->lengths) - 1;
		while ($len > 0)
		{
			if (!$this->matchSubstrings($len))
			{
				--$len;
			}
		}

		return implode('', $this->strings);
	}

	/**
	* Capture both ends of given length of strings being merged
	*
	* Will ignore strings that are too short
	*
	* @param  integer $len Substrings length
	* @return void
	*/
	protected function captureSubstrings($len)
	{
		$this->heads = $this->tails = [];
		foreach ($this->strings as $k => $string)
		{
			if ($this->lengths[$k] >= $len)
			{
				$head = substr($string, 0, $len);
				$tail = substr($string, -$len);
				$this->heads[$head][] = $k;
				$this->tails[$tail][] = $k;
			}
		}
	}

	/**
	* Match compatible strings and merge them together
	*
	* The algorithm matches strings that overlap each other. For example, "10111" and "11100" will
	* be matched at length 3 because the last 3 characters of the first string match the first 3
	* characters of the second string. The second string will be removed and merged into the first
	* string
	*
	* @param  integer $len Substrings length
	* @return bool         Whether any strings were merged
	*/
	protected function matchSubstrings($len)
	{
		$this->captureSubstrings($len);

		$merged = false;
		foreach (array_intersect_key($this->tails, $this->heads) as $tail => $tailKeys)
		{
			$headKeys = $this->heads[$tail];
			foreach ($tailKeys as $tailKey)
			{
				if (!isset($this->strings[$tailKey]))
				{
					continue;
				}

				foreach ($headKeys as $headKey)
				{
					if ($tailKey === $headKey || !isset($this->strings[$headKey]))
					{
						continue;
					}

					$this->strings[$tailKey] .= substr($this->strings[$headKey], $len);
					unset($this->strings[$headKey]);
					$merged = true;

					break;
				}
			}
		}

		return $merged;
	}

	/**
	* Convert a string made of 0s and 1s to raw bytes
	*
	* The character at pos #0 in the original string matches bit #0 of the returned string
	*
	* @param  string $str
	* @return string
	*/
	public static function toBin($str)
	{
		$bin = '';
		foreach (str_split($str, 8) as $chunk)
		{
			$bin .= chr(bindec(strrev($chunk)));
		}

		return $bin;
	}
}