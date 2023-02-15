using System;
using System.Collections.Generic;
using System.Linq;

namespace PKI.Utils {
	static class EnumFlags {
		public static IEnumerable<Int32> GetValues(Type inType) {
			Array arr = Enum.GetValues(inType);
			Int32[] rarr = new Int32[arr.Length];
			Array.Copy(arr, rarr, arr.Length);
			return rarr;
		}
		public static Boolean Contains<T>(IEnumerable<T> source, T value) {
			List<T> li = new List<T>(source);
			return li.Contains(value);
		}
		public static Int32[] GetEnabled(Type inType, Int32 value) {
			IEnumerable<Int32> values = GetValues(inType);
			return values.Where(item => (value & item) != 0).ToArray();
		}
		public static Int32 Add(IEnumerable<Int32> existingArr, Int32 exf, IEnumerable<Int32> added) {
			exf += added.Where(item => !Contains(existingArr, item)).Sum();
			return exf;
		}
		public static Int32 Remove(IEnumerable<Int32> existingArr, Int32 exf, IEnumerable<Int32> removed) {
			return removed.Where(item => !Contains(existingArr, item)).Aggregate(exf, (current, item) => current - item);
		}
	}
}
