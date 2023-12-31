﻿using System;
using System.Threading;

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
                        string connectionstring = "<connection string, remove and replace with a configuration based approach>";
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
