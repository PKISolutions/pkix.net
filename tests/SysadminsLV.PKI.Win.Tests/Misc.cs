using System;
using System.Collections.Generic;
using System.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace SysadminsLV.PKI.Win.Tests {
	public class TemplateSupportRow {
		public String Os { get; set; }
		public String Edition { get; set; }
		public Int32 TemplateVersion { get; set; }
		public Boolean Support { get; set; }
		public static IEnumerable<TemplateSupportRow> GenerateTable() {
			List<TemplateSupportRow> table = new List<TemplateSupportRow> {
				new TemplateSupportRow { Os = "2003", Edition = "Standard", TemplateVersion = 1, Support = true },
				new TemplateSupportRow { Os = "2003", Edition = "Standard", TemplateVersion = 2, Support = false },
				new TemplateSupportRow { Os = "2003", Edition = "Standard", TemplateVersion = 3, Support = false },
				new TemplateSupportRow { Os = "2003", Edition = "Standard", TemplateVersion = 4, Support = false },
				new TemplateSupportRow { Os = "2003", Edition = "Enterprise", TemplateVersion = 1, Support = true },
				new TemplateSupportRow { Os = "2003", Edition = "Enterprise", TemplateVersion = 2, Support = true },
				new TemplateSupportRow { Os = "2003", Edition = "Enterprise", TemplateVersion = 3, Support = false },
				new TemplateSupportRow { Os = "2003", Edition = "Enterprise", TemplateVersion = 4, Support = false },
				new TemplateSupportRow { Os = "2008", Edition = "Standard", TemplateVersion = 1, Support = true },
				new TemplateSupportRow { Os = "2008", Edition = "Standard", TemplateVersion = 2, Support = false },
				new TemplateSupportRow { Os = "2008", Edition = "Standard", TemplateVersion = 3, Support = false },
				new TemplateSupportRow { Os = "2008", Edition = "Standard", TemplateVersion = 4, Support = false },
				new TemplateSupportRow { Os = "2008", Edition = "Enterprise", TemplateVersion = 1, Support = true },
				new TemplateSupportRow { Os = "2008", Edition = "Enterprise", TemplateVersion = 2, Support = true },
				new TemplateSupportRow { Os = "2008", Edition = "Enterprise", TemplateVersion = 3, Support = true },
				new TemplateSupportRow { Os = "2008", Edition = "Enterprise", TemplateVersion = 4, Support = false },
				new TemplateSupportRow { Os = "2008R2", TemplateVersion = 1, Support = true },
				new TemplateSupportRow { Os = "2008R2", TemplateVersion = 2, Support = true },
				new TemplateSupportRow { Os = "2008R2", TemplateVersion = 3, Support = true },
				new TemplateSupportRow { Os = "2008R2", TemplateVersion = 4, Support = false },
				new TemplateSupportRow { Os = "2012", TemplateVersion = 1, Support = true },
				new TemplateSupportRow { Os = "2012", TemplateVersion = 2, Support = true },
				new TemplateSupportRow { Os = "2012", TemplateVersion = 3, Support = true },
				new TemplateSupportRow { Os = "2012", TemplateVersion = 4, Support = true },
				new TemplateSupportRow { Os = "2012R2", TemplateVersion = 1, Support = true },
				new TemplateSupportRow { Os = "2012R2", TemplateVersion = 2, Support = true },
				new TemplateSupportRow { Os = "2012R2", TemplateVersion = 3, Support = true },
				new TemplateSupportRow { Os = "2012R2", TemplateVersion = 4, Support = true },
				new TemplateSupportRow { Os = "2012R2-1", TemplateVersion = 1, Support = true },
				new TemplateSupportRow { Os = "2012R2-1", TemplateVersion = 2, Support = true },
				new TemplateSupportRow { Os = "2012R2-1", TemplateVersion = 3, Support = true },
				new TemplateSupportRow { Os = "2012R2-1", TemplateVersion = 4, Support = true },
			};
			return table;
		}
	}
	[TestClass]
	public class Misc {
		//        template support table
		// _______________________________________________________________
		// |     os          | template version |         result         |
		// |-----------------|------------------|------------------------|
		// |win2k3 Std       |     1/2/3/4      | true/false/false/false |
		// |win2k3 EE        |     1/2/3/4      | true/true/false/false  |
		// |win2k8 Std       |     1/2/3/4      | true/false/false/false |
		// |win2k8 EE        |     1/2/3/4      | true/true/true/false   |
		// |win2k8R2 All     |     1/2/3/4      | true/true/true/false   |
		// |win2k12 All      |     1/2/3/4      | true/true/true/true    |
		// |win2k12R2 All    |     1/2/3/4      | true/true/true/true    |
		// |win2k12R2-1 All  |     1/2/3/4      | true/true/true/true    |
		// |_________________|__________________|________________________|

		// 
		[TestMethod]
		public void IsSupported() {
			foreach (TemplateSupportRow row in TemplateSupportRow.GenerateTable()) {
				Boolean retValue = false;
				switch (row.Os) {
					case "2003":
						switch (row.TemplateVersion) {
							case 1: retValue = true; break;
							case 2:
								if (row.Edition == "Enterprise" || row.Edition == "Datacenter") { retValue = true; }
								break;
						}
						break;
					case "2008":
						switch (row.TemplateVersion) {
							case 1: retValue = true; break;
							case 2:
								if (row.Edition == "Enterprise" || row.Edition == "Datacenter") { retValue = true; }
								break;
							case 3:
								if (row.Edition == "Enterprise" || row.Edition == "Datacenter") { retValue = true; }
								break;
						}
						break;
					case "2008R2":
						if (row.TemplateVersion < 4) { retValue = true; }
						break;
					default: retValue = true; break;
				}
				Debug.WriteLine(
					"OS: " + row.Os + ", Edition: " + row.Edition + ", Template: " +
					row.TemplateVersion + ", Value: " + retValue
				);
				if (row.Support != retValue) { throw new Exception(); }
			}
		}
	}
}
