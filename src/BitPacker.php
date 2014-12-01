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
	* Merge an array strings into the shortest string possible
	*
	* Strings are expected to be made entirely of '0' and '1'. The result isn't guaranteed to be
	* optimal but it should be pretty close.
	*
	* @param  string[] $strings List of strings, each composed entirely of '0' and '1'
	* @return string
	*/
	static public function merge(array $strings)
	{
		$lengths = array_map('strlen', $strings);
		$len = max($lengths) - 1;

		while ($len > 0)
		{
			$heads = $tails = [];
			foreach ($strings as $k => $string)
			{
				if ($lengths[$k] >= $len)
				{
					$head = substr($string, 0, $len);
					$tail = substr($string, -$len);
					$heads[$head][] = $k;
					$tails[$tail][] = $k;
				}
			}

			$redo = false;
			foreach (array_intersect_key($tails, $heads) as $tail => $tailKeys)
			{
				$headKeys = $heads[$tail];
				foreach ($tailKeys as $tailKey)
				{
					if (!isset($strings[$tailKey]))
					{
						continue;
					}

					foreach ($headKeys as $headKey)
					{
						if ($tailKey === $headKey || !isset($strings[$headKey]))
						{
							continue;
						}

						$strings[$tailKey] .= substr($strings[$headKey], $len);
						unset($strings[$headKey]);
						$redo = true;

						break;
					}
				}
			}

			if (!$redo)
			{
				--$len;
			}
		}

		return implode('', $strings);
	}
}