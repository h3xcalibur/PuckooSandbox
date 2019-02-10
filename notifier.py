import inotify.adapters
import os
import conf

conf.readconf()

folder = conf.settings.folder
webfolder = conf.settings.webfolder

notifier = inotify.adapters.Inotify()
#notifier.add_watch('/var/www/html/uploads')
watchfolder = folder + "uploads"
managerscript = webfolder + "/manager.py"
notifier.add_watch(watchfolder)

for event in notifier.event_gen():
    if event is not None:
        # print event      # uncomment to see all events generated
        #print event
        if 'IN_MOVED_TO' in event[1]:
             print "file '{0}' created in '{1}'".format(event[3], event[2])
             virus_path = event[2] + "/" + event[3]
             #os.system("python /etc/puckoo/web_manager.py " + virus_path)
             os.system("python " + managerscript + " " + virus_path)
             print "Finished analysis."
