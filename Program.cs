using DatabaseAdapters;
using System;
using System.Collections.Generic;
using System.Configuration.Install;
using System.Linq;
using System.Reflection;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ThreatIntelligence
{
    internal class Program
    {
        static void Main(string[] args)
        {
            DateTime lastRun = DateTime.MinValue;

            try
            {
                while (true)
                {
                    if (lastRun == DateTime.MinValue || lastRun.Day != DateTime.UtcNow.Day)
                    {
                        string connectionstring = "Server=localhost;Database=Archlake;User Id=sa;Password=1jp4pwthnbhy!;";
                        ThreatList.processBlocklists(connectionstring);
                        lastRun = DateTime.Now;
                    }
                    Console.Out.WriteLine("---------- PROCESSING COMPLETE + " + DateTime.UtcNow.ToString("yyyy-MM-dd hh:mm:ss") +" -------------");
                    Thread.Sleep(60000);
                }
                
            }
            catch (Exception xyz)
            {
                System.Console.Out.WriteLine(xyz.Message);
                System.Console.Out.WriteLine(xyz.StackTrace);
            }
        }
    }
}
